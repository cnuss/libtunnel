// Package probe asks the edge whether a tunnel still exists.
//
// A provider that reaps an idle tunnel leaves its connections looking fine
// and the edge saying nothing, so nothing event-driven notices. The prober
// asks outright, by registering a spare connection and reading the edge's
// answer: a refusal is the tunnel being gone, whatever DNS still says about
// its hostname.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/crypto"
	"github.com/cloudflare/cloudflared/edgediscovery"
	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
	"github.com/cloudflare/cloudflared/features"
	"github.com/cloudflare/cloudflared/tunnelrpc"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/google/uuid"
	dns "github.com/ncruces/go-dns"
	"github.com/rs/zerolog"
	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/http2"
	"golang.org/x/net/websocket"

	"github.com/cnuss/libtunnel/v1alpha1/cloudflare/trust"
)

// Timeout bounds one probe end to end — discovery, dial, handshake, RPC.
const Timeout = 15 * time.Second

// probeConnIndex is the connection index the probe registers under. It must
// sit clear of the connector's own (0 to haConnections-1): the edge routes
// traffic to a registration on a held index, and the probe closing moments
// later strands it — measured as a five-second run of 530s on a live tunnel.
const probeConnIndex = 2

// BridgePath is where the provider's own host upgrades to the edge bridge: a
// WebSocket that carries the edge's TLS to region1.v2.argotunnel.com:7844,
// for a network that will not carry 7844 itself — one that allows HTTPS to
// that host and nothing else, at the strictest. The host is the provider's
// (see WithBridge) because it is the one host such a network already had to
// allow, for the mint. The bridge reads none of the bytes, so TLS still
// terminates at the edge.
const BridgePath = "/relay"

// DefaultBridge is the bridge on the default provider's host, which every
// prober has until WithBridge names another: a prober built on its own is
// no less likely to be on a network that will not carry 7844.
const DefaultBridge = "wss://tunnel.pizza" + BridgePath

// route is one way to the edge. The zero value is the one tried first when
// nothing is remembered.
type route int

const (
	// routeDirect dials the edge's own addresses on 7844.
	routeDirect route = iota
	// routeBridge upgrades the provider's host to a WebSocket and carries
	// the edge's TLS inside it.
	routeBridge
)

func (r route) String() string {
	switch r {
	case routeDirect:
		return "direct"
	case routeBridge:
		return "bridge"
	default:
		return fmt.Sprintf("route(%d)", int(r))
	}
}

// dialTimeout bounds one edge address. Short, because failing it is not the
// end of the ask — the bridge is tried next, and both have to fit inside the
// probe's budget.
const dialTimeout = 3 * time.Second

// bridgeMemo is how long a working bridge stays the first route tried before
// the direct edge is given another chance.
const bridgeMemo = 5 * time.Minute

// controlStreamTimeout bounds the wait for the edge to ask for the control
// stream. The roles invert on TCP — the probe serves and the edge requests —
// so an edge that accepts the connection and then says nothing would
// otherwise hold the whole ask, and the route that might have answered never
// gets tried. Same five seconds the registration RPC gets.
const controlStreamTimeout = 5 * time.Second

// maxBackoff caps the wait between attempts, which otherwise grows a second
// per attempt for as long as the caller's context lives.
const maxBackoff = 5 * time.Second

// edgeSRVService is the SRV service cloudflared discovers the edge through.
const edgeSRVService = "v2-origintunneld"

// dohEndpoint is one DNS-over-HTTPS resolver. The addresses are pinned so the
// check does not need the machine's resolver to find its way to a resolver.
type dohEndpoint struct {
	uri       string
	addresses []string
}

// dohEndpoints are asked in order. Public resolvers rather than the machine's:
// a captive portal, a split-horizon corporate resolver, or a container that
// lost its resolv.conf will happily report a perfectly good hostname as
// nonexistent, and this check turns that answer into a report telling a
// caller to discard its tunnel. Over HTTPS rather than port 53 because plenty
// of networks block or hijack 53. Two operators, so one having a bad day does
// not decide.
var dohEndpoints = []dohEndpoint{
	{"https://cloudflare-dns.com/dns-query", []string{"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"}},
	{"https://dns.google/dns-query", []string{"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"}},
}

// dohTimeout bounds one endpoint. The whole check has to fit inside the
// probe's budget alongside a handshake.
const dohTimeout = 2 * time.Second

// Prober asks whether a tunnel still exists. One question per Probe and no
// state kept between them: when to ask, and what to do with the answer, is
// the caller's. Build one with New and the With* methods.
type Prober struct {
	id         string
	hostname   string
	accountTag string
	secret     []byte
	version    string
	rootCAs    *x509.CertPool
	log        *zerolog.Logger

	resolversOnce sync.Once
	resolvers     []*net.Resolver

	tlsConfigs     map[connection.Protocol]*tls.Config
	tlsConfigsOnce sync.Once

	// bridges are the WebSockets that carry the edge's TLS, in the order
	// tried: the one on the provider's host when WithBridge named one, then
	// DefaultBridge — a provider without a bridge of its own (trycloudflare)
	// is still reached through tunnel.pizza's, since what it carries is
	// Cloudflare's edge, not that provider.
	bridges []*url.URL
	// bridgeTLS is the outer TLS to the bridge's host. Nil verifies against
	// the system roots, which is what an ordinary host on 443 wants; a test
	// standing up its own bridge sets its own.
	bridgeTLS *tls.Config

	// preferred is the route that answered last, tried first until
	// preferredUntil. A network that refused 7844 once refuses it still,
	// and waiting out that refusal every time costs dialTimeout per ask —
	// but not forever, since the machine this runs on changes networks.
	routeMu        sync.Mutex
	preferred      route
	preferredUntil time.Time
}

// New returns a Prober with every knob defaulted: reports an "unknown" client
// version, trusts the roots libtunnel ships (trust.Pool), and logs nowhere.
// Chain the With* methods to change any of it — a zero argument leaves the
// default; WithID, WithAccountTag and WithSecret have no default worth
// having.
func New() *Prober {
	nop := zerolog.Nop()
	return (&Prober{
		version: "unknown",
		rootCAs: trust.Pool(),
		log:     &nop,
	}).WithBridge(DefaultBridge)
}

// WithID names the tunnel to ask about (a UUID). One that does not parse
// fails the registration, after the dial.
func (p *Prober) WithID(id string) *Prober {
	if id != "" {
		p.id = id
	}
	return p
}

// WithHostname sets the tunnel's public hostname. It names the tunnel in the
// probe's own logs and backs LookupHost; the verdict does not depend on it.
func (p *Prober) WithHostname(hostname string) *Prober {
	if hostname != "" {
		p.hostname = hostname
	}
	return p
}

// WithAccountTag sets the account the registration presents.
func (p *Prober) WithAccountTag(tag string) *Prober {
	if tag != "" {
		p.accountTag = tag
	}
	return p
}

// WithSecret sets the tunnel secret the registration presents.
func (p *Prober) WithSecret(secret []byte) *Prober {
	if len(secret) > 0 {
		p.secret = secret
	}
	return p
}

// WithVersion sets the client version reported at registration.
func (p *Prober) WithVersion(version string) *Prober {
	if version != "" {
		p.version = version
	}
	return p
}

// WithRootCAs sets the trust set for the edge and the DoH resolvers.
// Default: trust.Pool, the host's store plus the roots libtunnel ships.
func (p *Prober) WithRootCAs(pool *x509.CertPool) *Prober {
	if pool != nil {
		p.rootCAs = pool
	}
	return p
}

// WithBridge names the WebSocket endpoint (ws or wss) that carries the edge's
// TLS through the provider's host — tried after the edge's own addresses, and
// before DefaultBridge, which stays as the fallback. An empty or unusable
// value leaves DefaultBridge alone in place.
func (p *Prober) WithBridge(endpoint string) *Prober {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "ws" && u.Scheme != "wss") {
		return p
	}
	fallback, _ := url.Parse(DefaultBridge)
	p.bridges = []*url.URL{u}
	if u.String() != fallback.String() {
		p.bridges = append(p.bridges, fallback)
	}
	return p
}

// Bridge reports the bridge tried first: the one WithBridge named, else
// DefaultBridge.
func (p *Prober) Bridge() string {
	if len(p.bridges) == 0 {
		return ""
	}
	return p.bridges[0].String()
}

// WithLogger sets where the probe logs.
func (p *Prober) WithLogger(log *zerolog.Logger) *Prober {
	if log != nil {
		p.log = log
	}
	return p
}

// TLSConfigs is the edge TLS config per protocol, for a caller that dials the
// edge itself — cloudflared's supervisor takes a map of exactly this shape.
// It asks nothing of the network: a config is a pure function of the trust
// set, so it is ready before anything has been reached, and every protocol
// gets an entry because a nil config is a panic one layer down.
func (p *Prober) TLSConfigs() map[connection.Protocol]*tls.Config {
	p.tlsConfigsOnce.Do(func() {
		p.tlsConfigs = make(map[connection.Protocol]*tls.Config, len(connection.ProtocolList))
		for _, protocol := range connection.ProtocolList {
			settings := protocol.TLSSettings()
			if settings == nil {
				continue
			}
			plain := &tls.Config{
				ServerName: settings.ServerName,
				NextProtos: settings.NextProtos,
				RootCAs:    p.rootCAs,
			}
			config, err := crypto.TLSConfigWithCurvePreferences(plain, features.PostQuantumPrefer)
			if err != nil {
				// Curve preferences are all that can fail here, and they fail
				// the same way every time. A config without them still dials
				// the edge; no config at all panics the supervisor.
				p.log.Warn().Err(err).Str("protocol", protocol.String()).
					Msg("edge TLS curve preferences, using the config without them")
				config = plain
			}
			p.tlsConfigs[protocol] = config
		}
	})
	return p.tlsConfigs
}

// ErrGone is Probe's answer when the tunnel no longer exists. ErrInUse is
// its answer when the tunnel exists and another connector holds the index
// the probe registered under: the edge only refuses a registration as a
// duplicate for a tunnel it has.
var (
	ErrInUse = errors.New("tunnel in use")
	ErrGone  = errors.New("tunnel is gone")
	ErrRetry = errors.New("tunnel should retry")
	// ErrOrphaned is an ErrGone the provider can undo: the tunnel is gone
	// but the record that reserved its hostname is not, and a mint replaying
	// that record id recreates the tunnel under the same name. Every ErrGone
	// ends a tunnel; this one says the next one can have the same hostname.
	ErrOrphaned = errors.New("hostname outlived the tunnel")
)

// Probe asks the edge once, retrying while the answer is that it could not be
// asked, and reports what the edge said. ctx bounds the whole ask.
//
// cancel ends the ask, and carries the one verdict that is not returned: a
// tunnel whose hostname outlived it comes back as nil with ErrOrphaned as the
// context's cause. A caller that only reads the error carries on — there is a
// hostname to rebuild on — and one that reads context.Cause learns it should
// mint with the record id to get that name back.
func (p *Prober) Probe(ctx context.Context, cancel context.CancelCauseFunc) error {
	defer cancel(nil)

	// A floor for a caller who bounded nothing: the loop below ends when ctx
	// does, and a network that cannot reach the edge answers ErrRetry for as
	// long as it is asked.
	if _, bounded := ctx.Deadline(); !bounded {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, Timeout)
		defer stop()
	}

	for attempt := 1; ; attempt++ {
		err := p.probeHTTP2(ctx)
		if errors.Is(err, ErrOrphaned) {
			// First cancel wins, so the deferred one leaves this in place.
			cancel(err)
			return nil
		}
		if !errors.Is(err, ErrRetry) {
			return err
		}
		p.log.Debug().Err(err).Int("attempt", attempt).Msg("probe retrying")

		// The wait is where cancellation lands: an ask that fails because ctx
		// ended is an ErrRetry like any other, so the loop only learns it here.
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w after %d attempts: %w", ErrRetry, attempt, context.Cause(ctx))
		case <-time.After(min(time.Duration(attempt)*time.Second, maxBackoff)):
		}
	}
}

// EdgeAddrs is the edge address list for a caller that dials the edge itself,
// or nil to leave it to that caller's own discovery — cloudflared's supervisor
// takes exactly this, and treats a non-empty list as the whole edge.
//
// It decides by dialing, in the order the last ask ended with — the hint
// probe usually just learned which route this network carries, and the
// direct timeout need not be paid twice — the edge's own addresses first
// when nothing is remembered, the bridge second, and
// whichever answers is what the tunnel should use for its life. Only the
// handshake is spent, not a registration, so nothing is left behind at the
// edge and no connection index is taken. Nothing answering returns nil, which
// leaves the caller to discover and retry as it would have anyway.
func (p *Prober) EdgeAddrs(ctx context.Context) []string {
	tlsConfig := p.TLSConfigs()[connection.HTTP2]

	for _, r := range p.routes() {
		conn, err := p.dialEdge(ctx, tlsConfig, r)
		if err != nil {
			p.log.Debug().Err(err).Stringer("route", r).Msg("no answer on this route")
			continue
		}
		conn.Close()

		// The probe starts on this route too: they are asking the same
		// network the same question.
		p.remember(r)

		if r == routeDirect {
			return nil
		}
		p.log.Info().Stringer("route", r).
			Msg("edge unreachable at its own addresses, pinning the tunnel to this route")

		// The caller dials these addresses itself and knows nothing of
		// WebSockets, so it gets a loopback address instead and the
		// forwarder carries each connection on through the bridge.
		local, err := p.forward(ctx, r, p.dialBridge)
		if err != nil {
			p.log.Warn().Err(err).Msg("no forwarder for this route, leaving the edge to the caller")
			return nil
		}
		p.log.Info().Stringer("route", r).Str("listening", local).
			Msg("carrying the tunnel through the forwarder")
		return []string{local, local}
	}
	return nil
}

// all is every route this prober has, in the order they are tried when
// nothing is remembered: the edge itself, then the bridge when a provider
// host was named for it.
func (p *Prober) all() []route {
	routes := []route{routeDirect}
	if len(p.bridges) > 0 {
		routes = append(routes, routeBridge)
	}
	return routes
}

// routes is the order to try: whichever answered last first, for as long as
// the memo holds, then the rest in their own order. Every route is tried
// every time, so a network that starts carrying 7844 again is noticed, and
// one that stopped is not waited on twice.
func (p *Prober) routes() []route {
	all := p.all()
	p.routeMu.Lock()
	first := p.preferred
	if time.Now().After(p.preferredUntil) {
		first = routeDirect
	}
	p.routeMu.Unlock()
	if first == routeDirect {
		return all
	}
	ordered := []route{first}
	for _, r := range all {
		if r != first {
			ordered = append(ordered, r)
		}
	}
	return ordered
}

// remember records the route that answered, so the next ask starts there.
// The edge's own addresses need no remembering: they are first anyway.
func (p *Prober) remember(r route) {
	p.routeMu.Lock()
	defer p.routeMu.Unlock()
	p.preferred = r
	p.preferredUntil = time.Time{}
	if r != routeDirect {
		p.preferredUntil = time.Now().Add(bridgeMemo)
	}
}

// proxyFor reports the proxy the environment names for target, or nil when it
// names none. The target is modelled as a URL of the given scheme — https for
// a TLS host, which HTTPS_PROXY answers for — and NO_PROXY is honored on the
// way.
//
// Read afresh each time rather than through http.ProxyFromEnvironment, which
// caches the environment behind a sync.Once on first use anywhere in the
// process — a tunnel built after that call would not see its own settings.
func proxyFor(scheme, target string) *url.URL {
	proxy, err := httpproxy.FromEnvironment().ProxyFunc()(&url.URL{Scheme: scheme, Host: target})
	if err != nil {
		return nil
	}
	return proxy
}

// dialViaProxy opens a TCP tunnel to target through proxy and returns it. The
// bytes that follow are not read or written by anything here, so TLS still
// terminates at the far end and the pinned trust set still decides.
func dialViaProxy(ctx context.Context, proxy *url.URL, target string) (net.Conn, error) {
	address := proxy.Host
	if proxy.Port() == "" {
		if proxy.Scheme == "https" {
			address = net.JoinHostPort(address, "443")
		} else {
			address = net.JoinHostPort(address, "80")
		}
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", address, err)
	}

	// The whole CONNECT exchange under one deadline, cleared before the
	// caller gets the socket: what it carries afterwards has its own.
	if err := conn.SetDeadline(time.Now().Add(dialTimeout)); err != nil {
		conn.Close()
		return nil, err
	}

	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: http.Header{},
	}
	if user := proxy.User; user != nil {
		password, _ := user.Password()
		request.Header.Set("Proxy-Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(user.Username()+":"+password)))
	}
	if err := request.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT to %s: %w", address, err)
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response from %s: %w", address, err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy %s refused CONNECT to %s: %s", address, target, response.Status)
	}
	// Anything buffered past the response is payload the proxy sent before
	// the tunnel opened, and the caller's TLS handshake would never see it.
	if reader.Buffered() > 0 {
		conn.Close()
		return nil, fmt.Errorf("proxy %s sent %d bytes before the tunnel to %s",
			address, reader.Buffered(), target)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// forward is how a caller that can only dial an address reaches a route it
// cannot: a loopback address it dials as if it were the edge, with every
// connection carried on by dial. cloudflared's supervisor takes addresses and
// dials them itself, and 127.0.0.1 is the one address every network allows.
//
// The listener lives as long as ctx. Nothing here reads the bytes it copies,
// so the supervisor's TLS still terminates at the edge.
func (p *Prober) forward(ctx context.Context, r route, dial func(context.Context) (net.Conn, error)) (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen for the %s forwarder: %w", r, err)
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	go func() {
		for {
			local, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer local.Close()
				remote, err := dial(ctx)
				if err != nil {
					p.log.Debug().Err(err).Stringer("route", r).Msg("the route would not carry this connection")
					return
				}
				defer remote.Close()
				go func() { _, _ = io.Copy(remote, local) }()
				_, _ = io.Copy(local, remote)
			}()
		}
	}()

	return listener.Addr().String(), nil
}

// dialBridge opens the WebSocket to the first bridge that answers and returns
// it as a stream: the outer TLS is the bridge host's own, verified against
// the system roots like any host on 443, and what the caller writes rides
// the frames unread. Through the proxy where the environment names one,
// since a network that needs this route usually has one.
func (p *Prober) dialBridge(ctx context.Context) (net.Conn, error) {
	if len(p.bridges) == 0 {
		return nil, errors.New("no bridge named")
	}
	var err error
	for _, bridge := range p.bridges {
		var conn net.Conn
		conn, err = p.dialOneBridge(ctx, bridge)
		if err == nil {
			return conn, nil
		}
		p.log.Debug().Err(err).Str("bridge", bridge.String()).Msg("bridge did not answer")
	}
	return nil, err
}

func (p *Prober) dialOneBridge(ctx context.Context, bridge *url.URL) (net.Conn, error) {
	secure := bridge.Scheme == "wss"
	scheme, port := "http", "80"
	if secure {
		scheme, port = "https", "443"
	}
	if bridge.Port() != "" {
		port = bridge.Port()
	}
	host := bridge.Hostname()
	target := net.JoinHostPort(host, port)

	p.log.Info().Str("bridge", bridge.String()).Msg("reaching the edge through the bridge")

	var raw net.Conn
	var err error
	if proxy := proxyFor(scheme, target); proxy != nil {
		p.log.Info().Str("proxy", proxy.Host).Str("target", target).
			Msg("reaching the bridge through the proxy")
		raw, err = dialViaProxy(ctx, proxy, target)
	} else {
		raw, err = (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", target)
	}
	if err != nil {
		return nil, err
	}

	stream := raw
	if secure {
		config := p.bridgeTLS
		if config == nil {
			config = &tls.Config{ServerName: host}
		}
		tlsConn := tls.Client(raw, config)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS to %s: %w", target, err)
		}
		stream = tlsConn
	}

	// The upgrade under one deadline, like CONNECT: what follows has its
	// own.
	if err := stream.SetDeadline(time.Now().Add(dialTimeout)); err != nil {
		stream.Close()
		return nil, err
	}
	config, err := websocket.NewConfig(bridge.String(), scheme+"://"+host+"/")
	if err != nil {
		stream.Close()
		return nil, err
	}
	ws, err := websocket.NewClient(config, stream)
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("upgrade %s: %w", bridge, err)
	}
	if err := stream.SetDeadline(time.Time{}); err != nil {
		ws.Close()
		return nil, err
	}
	ws.PayloadType = websocket.BinaryFrame
	return ws, nil
}

// dialEdge opens a TLS connection to the edge by r: at one of its own
// addresses on 7844, or inside a WebSocket to the bridge. Neither reads the
// bytes, so the certificate verified is origintunneld's on both routes and
// one TLS config serves for either.
func (p *Prober) dialEdge(ctx context.Context, tlsConfig *tls.Config, r route) (net.Conn, error) {
	if r == routeBridge {
		raw, err := p.dialBridge(ctx)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, tlsConfig)
		if err := conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS to the edge through the bridge: %w", err)
		}
		return conn, nil
	}

	regions, err := allregions.EdgeDiscovery(p.log, edgeSRVService)
	if err != nil {
		return nil, fmt.Errorf("edge discovery: %w", err)
	}
	for _, region := range regions {
		for _, candidate := range region {
			if candidate.TCP == nil || candidate.TCP.IP.To4() == nil {
				continue
			}
			return edgediscovery.DialEdge(ctx, dialTimeout, tlsConfig, candidate.TCP, nil)
		}
	}
	return nil, errors.New("edge discovery returned no IPv4 TCP endpoint")
}

// probeHTTP2 registers a spare connection over TCP and reads the edge's
// answer. cloudflared dials TCP, serves HTTP/2 on the socket it dialed, and
// the edge opens the control stream by requesting it — so the probe stands
// up a server and waits to be asked, rather than asking.
func (p *Prober) probeHTTP2(ctx context.Context) error {
	tunnelID, err := uuid.Parse(p.id)
	if err != nil {
		return fmt.Errorf("%w: %q is not a tunnel id: %w", ErrGone, p.id, err)
	}

	tlsConfig := p.TLSConfigs()[connection.HTTP2]

	var conn net.Conn
	var via route
	for _, r := range p.routes() {
		conn, err = p.dialEdge(ctx, tlsConfig, r)
		if err == nil {
			via = r
			break
		}
		p.log.Debug().Err(err).Stringer("route", r).Msg("no answer on this route")
	}
	if err != nil {
		// No route reached the edge, so the edge never ruled: this is a
		// network with no way out, not a tunnel that stopped existing.
		return fmt.Errorf("%w: no way to the edge: %w", ErrRetry, err)
	}
	p.remember(via)

	defer conn.Close()

	// What the registration reports as the edge it reached: the address this
	// connection actually landed on, which is the bridge's when the bridge
	// carried it.
	var edgeIP net.IP
	if remote, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		edgeIP = remote.IP
	}

	// Buffered, so the handler can finish even when ctx wins the race below
	// and nothing is left reading.
	type answer struct {
		details *pogs.ConnectionDetails
		err     error
	}
	answered := make(chan answer, 1)

	go (&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
		Context: ctx,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// The edge opens other streams on this connection for its own
			// reasons; only the control stream carries the registration.
			if r.Header.Get(connection.InternalUpgradeHeader) != connection.ControlStreamUpgrade {
				return
			}
			rw, err := connection.NewHTTP2RespWriter(r, w, connection.TypeControlStream, p.log)
			if err != nil {
				// Pre-classified: the stream never formed, so the edge never
				// ruled on the tunnel.
				answered <- answer{err: fmt.Errorf("%w: control stream: %w", ErrRetry, err)}
				return
			}

			client := tunnelrpc.NewRegistrationClient(r.Context(), rw, 5*time.Second)
			defer client.Close()

			// A real UUID: the edge validates the client id before the
			// credentials, so an empty one is refused for the wrong reason.
			clientID := uuid.New()
			details, err := client.RegisterConnection(r.Context(), pogs.TunnelAuth{
				AccountTag:   p.accountTag,
				TunnelSecret: p.secret,
			}, tunnelID, &pogs.ConnectionOptions{
				Client: pogs.ClientInfo{
					ClientID: clientID[:],
					Version:  p.version,
					Arch:     runtime.GOOS + "_" + runtime.GOARCH,
				},
			}, probeConnIndex, edgeIP)
			if err == nil {
				// Let go of the slot before the socket goes: the edge routes
				// to a registered connection until it is unregistered or
				// noticed dead, and a probe that just hung up would leave
				// its index answering 502 for the next few seconds.
				if err := client.GracefulShutdown(r.Context(), 5*time.Second); err != nil {
					p.log.Debug().Err(err).Msg("probe could not unregister; the edge will notice the closed connection")
				}
			}
			answered <- answer{details: details, err: err}
		}),
	})

	var got answer
	select {
	case got = <-answered:
	case <-time.After(controlStreamTimeout):
		return fmt.Errorf("%w: edge opened no control stream in %s", ErrRetry, controlStreamTimeout)
	case <-ctx.Done():
		return fmt.Errorf("%w: edge opened no control stream: %w", ErrRetry, context.Cause(ctx))
	}

	if got.err == nil {
		p.log.Info().Any("details", got.details).Str("hostname", p.hostname).Msg("probe success")
		return nil
	} else if errors.Is(got.err, ErrRetry) {
		return got.err
	} else if ctx.Err() != nil {
		// An ask cut short is not an answer: the edge never ruled.
		return fmt.Errorf("%w: registration cut short: %w", ErrRetry, context.Cause(ctx))
	} else if strings.Contains(got.err.Error(), connection.DuplicateConnectionError) {
		p.log.Info().Msg("duplicate connection detected")
		return fmt.Errorf("%w: index %d: %w", ErrInUse, probeConnIndex, got.err)
	}

	// The edge ruled on the credential it was given, and the tunnel is gone
	// whatever DNS says — weighing the two against each other vouched for
	// dead specs (#243). What the hostname does now says something else:
	// whether anything is left to rebuild with. A record that still resolves
	// is one the provider recreates the tunnel under, so a caller holding
	// its record id gets the same hostname back by minting with it; a name
	// that went with the tunnel has nothing to replay. Neither answer, and
	// no answer at all, changes the verdict.
	if p.hostname != "" {
		if resolved, err := p.LookupHost(ctx, p.hostname); err == nil {
			p.log.Info().Str("hostname", p.hostname).Str("resolved", resolved).Err(got.err).
				Msg("tunnel is gone, its hostname remains: minting with the record id recreates it")
			return fmt.Errorf("%w: %w: edge refused the connection: %w", ErrGone, ErrOrphaned, got.err)
		}
	}
	return fmt.Errorf("%w: edge refused the connection: %w", ErrGone, got.err)
}

func (p *Prober) LookupHost(ctx context.Context, host string) (string, error) {
	var lastErr error
	for _, resolver := range p.dohResolvers() {
		if ctx.Err() != nil {
			return "", fmt.Errorf("%w: %w", ErrRetry, ctx.Err())
		}
		lookup, cancel := context.WithTimeout(ctx, dohTimeout)
		addrs, err := resolver.LookupHost(lookup, host)
		cancel()
		if err == nil && len(addrs) > 0 {
			return addrs[0], nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no DoH resolver answered")
	}
	var dnsErr *net.DNSError
	if errors.As(lastErr, &dnsErr) && dnsErr.IsNotFound {
		return "", lastErr
	}
	return "", fmt.Errorf("%w: %w", ErrRetry, lastErr)
}

// dohResolvers builds the resolvers once, dropping any that will not
// construct. Lazily, so a tunnel that is never asked never pays for the TLS
// setup.
func (p *Prober) dohResolvers() []*net.Resolver {
	p.resolversOnce.Do(func() {
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.rootCAs}}
		for _, endpoint := range dohEndpoints {
			resolver, err := dns.NewDoHResolver(endpoint.uri,
				dns.DoHAddresses(endpoint.addresses...),
				dns.DoHTransport(transport),
			)
			if err != nil {
				continue
			}
			p.resolvers = append(p.resolvers, resolver)
		}
	})
	return p.resolvers
}
