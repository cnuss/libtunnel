// Package probe asks the edge whether a tunnel still exists.
//
// A provider that reaps an idle tunnel leaves its connections looking fine
// and the edge saying nothing, so nothing event-driven notices. The prober
// asks outright, by registering a spare connection and reading the edge's
// answer — and where that answer is a refusal, by checking whether the
// hostname still resolves, since a reaped tunnel loses its record with it.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	"golang.org/x/net/http2"

	"github.com/cnuss/libtunnel/v1alpha1/cloudflare/trust"
)

// Timeout bounds one probe end to end — discovery, dial, handshake, RPC.
const Timeout = 15 * time.Second

// probeConnIndex is the connection index the probe registers under. It must
// sit clear of the connector's own (0 to haConnections-1): the edge routes
// traffic to a registration on a held index, and the probe closing moments
// later strands it — measured as a five-second run of 530s on a live tunnel.
const probeConnIndex = 2

// relayHost fronts the edge on a port and an address a hostile network is
// likelier to allow: it forwards TCP to region1.v2.argotunnel.com:7844 and
// reads none of it, so TLS still terminates at the edge.
const (
	relayHost = "relay.tunnel.pizza"
	relayPort = 443
)

// dialTimeout bounds one edge address. Short, because failing it is not the
// end of the ask — the relay is tried next, and both have to fit inside the
// probe's budget.
const dialTimeout = 3 * time.Second

// relayMemo is how long a working relay stays the first route tried before
// the direct edge is given another chance.
const relayMemo = 5 * time.Minute

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

	// relayUntil is how long the relay stays the first thing tried. A
	// network that refused 7844 once refuses it still, and waiting out that
	// refusal every time costs dialTimeout per ask — but not forever, since
	// the machine this runs on changes networks.
	relayMu    sync.Mutex
	relayUntil time.Time
}

// New returns a Prober with every knob defaulted: reports an "unknown" client
// version, trusts the roots libtunnel ships (trust.Pool), and logs nowhere.
// Chain the With* methods to change any of it — a zero argument leaves the
// default; WithID, WithAccountTag and WithSecret have no default worth
// having.
func New() *Prober {
	nop := zerolog.Nop()
	return &Prober{
		version: "unknown",
		rootCAs: trust.Pool(),
		log:     &nop,
	}
}

// WithID names the tunnel to ask about (a UUID). One that does not parse
// fails the registration, after the dial.
func (p *Prober) WithID(id string) *Prober {
	if id != "" {
		p.id = id
	}
	return p
}

// WithHostname sets the tunnel's public hostname, which a refused
// registration is checked against; a :port suffix is ignored. Without one a
// refusal is taken at face value.
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
)

func (p *Prober) Probe(ctx context.Context, cancel context.CancelFunc) error {
	defer cancel()

	for attempt := 1; ; attempt++ {
		err := p.probeHTTP2(ctx)
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
// It decides by dialing: the edge's own addresses first, the relay second, and
// whichever answers is what the tunnel should use for its life. Only the
// handshake is spent, not a registration, so nothing is left behind at the
// edge and no connection index is taken. Nothing answering returns nil, which
// leaves the caller to discover and retry as it would have anyway.
func (p *Prober) EdgeAddrs(ctx context.Context) []string {
	tlsConfig := p.TLSConfigs()[connection.HTTP2]

	for _, relay := range [2]bool{false, true} {
		conn, err := p.dialEdge(ctx, tlsConfig, relay)
		if err != nil {
			p.log.Debug().Err(err).Bool("relay", relay).Msg("no answer on this route")
			continue
		}
		conn.Close()

		// The probe starts on this route too: they are asking the same
		// network the same question.
		p.relayMu.Lock()
		if relay {
			p.relayUntil = time.Now().Add(relayMemo)
		} else {
			p.relayUntil = time.Time{}
		}
		p.relayMu.Unlock()

		if !relay {
			return nil
		}
		p.log.Info().Str("relay", relayHost).
			Msg("edge unreachable at its own addresses, pinning the tunnel to the relay")

		// Twice, because the list is split across two regions by index and a
		// single entry leaves one of them empty — with nowhere to put the
		// second HA connection.
		addr := fmt.Sprintf("%s:%d", relayHost, relayPort)
		return []string{addr, addr}
	}
	return nil
}

// dialEdge opens a TLS connection to the edge, either at one of its own
// addresses on 7844 or through the relay on 443. The relay forwards bytes
// without reading them, so the certificate verified is origintunneld's on
// both routes and one TLS config serves for either.
func (p *Prober) dialEdge(ctx context.Context, tlsConfig *tls.Config, viaRelay bool) (net.Conn, error) {
	if viaRelay {
		// Info: the relay is a detour worth seeing in a log, and reaching for
		// it says something about the network this is running on.
		p.log.Info().Str("relay", relayHost).Msg("reaching the edge through the relay")

		ips, err := net.LookupIP(relayHost)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", relayHost, err)
		}
		for _, ip := range ips {
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			addr := &net.TCPAddr{IP: v4, Port: relayPort}
			conn, err := edgediscovery.DialEdge(ctx, dialTimeout, tlsConfig, addr, nil)
			if err == nil {
				return conn, nil
			}
			p.log.Debug().Err(err).Str("relay", addr.String()).Msg("relay did not answer")
		}
		return nil, fmt.Errorf("%s has no address that answered", relayHost)
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

	// A refusal on its own does not end a tunnel — the hostname is what tells
	// a reap from a refusal — so without one there is no verdict to be had
	// and nothing worth dialing for.
	if p.hostname == "" {
		// Not ErrRetry: asking again cannot conjure a hostname, and not
		// ErrGone: nothing was asked. A caller that built the prober this
		// way gets told so once.
		return errors.New("no hostname to weigh a refusal against")
	}

	tlsConfig := p.TLSConfigs()[connection.HTTP2]

	// Whichever route worked last goes first. The order is the only thing
	// remembered: both are tried every time, so a network that starts
	// carrying 7844 again is noticed, and one that stops is not waited on
	// twice.
	p.relayMu.Lock()
	relayFirst := time.Now().Before(p.relayUntil)
	p.relayMu.Unlock()

	var conn net.Conn
	var viaRelay bool
	for _, relay := range [2]bool{relayFirst, !relayFirst} {
		conn, err = p.dialEdge(ctx, tlsConfig, relay)
		if err == nil {
			viaRelay = relay
			break
		}
		p.log.Debug().Err(err).Bool("relay", relay).Msg("no answer on this route")
	}
	if err != nil {
		// Neither route reached the edge, so the edge never ruled: this is a
		// network with no way out, not a tunnel that stopped existing.
		return fmt.Errorf("%w: no way to the edge: %w", ErrRetry, err)
	}

	p.relayMu.Lock()
	if viaRelay {
		p.relayUntil = time.Now().Add(relayMemo)
	} else {
		p.relayUntil = time.Time{}
	}
	p.relayMu.Unlock()

	defer conn.Close()

	// What the registration reports as the edge it reached: the address this
	// connection actually landed on, which is the relay's when the relay
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
			answered <- answer{details: details, err: err}
		}),
	})

	var got answer
	select {
	case got = <-answered:
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

	// The edge refused. A provider that reaps a tunnel deletes the record
	// with it, so what the name does now is what says whether that happened:
	// still resolving means this tunnel was not reaped, and no answer at all
	// leaves the refusal standing alone, which is not enough to end a tunnel.
	host := p.hostname
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	resolved, err := p.LookupHost(ctx, host)
	if err == nil {
		p.log.Debug().Str("host", host).Str("resolved", resolved).Err(got.err).
			Msg("edge refused the connection but the hostname still resolves")
		return nil
	} else if errors.Is(err, ErrRetry) {
		return fmt.Errorf("edge refused the connection and %s could not be resolved: %w", host, err)
	} else {
		return fmt.Errorf("%w: edge refused the connection (%v) and %s no longer resolves: %w",
			ErrGone, got.err, host, err)
	}
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
