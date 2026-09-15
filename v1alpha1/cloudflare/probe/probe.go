// Package probe asks the edge whether a tunnel still exists.
//
// A provider that reaps an idle tunnel leaves its connections looking fine
// and the edge saying nothing, so nothing event-driven notices. The prober
// asks outright, on an interval: first whether the hostname still resolves
// (a reaped tunnel loses its record), then by registering a spare connection
// and reading the edge's answer.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/connection/dialopts"
	"github.com/cloudflare/cloudflared/crypto"
	"github.com/cloudflare/cloudflared/edgediscovery"
	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
	"github.com/cloudflare/cloudflared/features"
	cfquic "github.com/cloudflare/cloudflared/quic"
	"github.com/cloudflare/cloudflared/tunnelrpc"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/google/uuid"
	dns "github.com/ncruces/go-dns"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"

	"github.com/cnuss/libtunnel/v1alpha1/cloudflare/trust"
)

// DefaultInterval is how often a Prober asks. Every tick on a healthy tunnel
// spends a registration, so this is a standing cost for the life of the
// tunnel rather than a timeout to tune down. A client notices a deleted
// tunnel at ~12s over QUIC and ~188s over http2 on its own; this sits
// between them.
const DefaultInterval = 30 * time.Second

// Timeout bounds one probe end to end — discovery, dial, handshake, RPC.
// Run gives each of its probes this much; a direct Probe caller picks its
// own.
const Timeout = 15 * time.Second

// handshakeTimeout and idleTimeout bound one edge address, keeping a dead one
// cheap enough that the walk reaches the live ones. Tighter than cloudflared's
// own (5s and 5s), which are tuned for a connector that must not give up on
// the address it has; a probe walking twenty-odd addresses inside timeout
// abandons a slow one instead.
const (
	handshakeTimeout = 2 * time.Second
	idleTimeout      = 3 * time.Second
)

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

// Prober asks whether a tunnel still exists and reports when it does not.
// Reporting only: cloudflared keeps retrying either way, and ending the
// tunnel on the strength of one probe is the caller's call to make. Nothing
// here remembers having answered — a tunnel that goes away twice is reported
// twice. Build one with New and the With* methods.
type Prober struct {
	id         string
	hostname   string
	accountTag string
	secret     []byte
	// protocol is what Probe asks over when no selector is set.
	protocol         connection.Protocol
	protocolSelector connection.ProtocolSelector
	connIndex        uint8
	version          string
	rootCAs          *x509.CertPool
	log              *zerolog.Logger
	interval         time.Duration
	gone             func()

	resolversOnce sync.Once
	resolvers     []*net.Resolver
}

// New returns a Prober with every knob defaulted: asks every
// DefaultInterval over http2 as connection index 1, reports an "unknown"
// client version, trusts the roots libtunnel ships (trust.Pool), logs
// nowhere, and reports to no one. Chain the With* methods to change any of it — a zero
// argument leaves the default; WithID, WithAccountTag and WithSecret have no
// default worth having.
func New() *Prober {
	nop := zerolog.Nop()
	return &Prober{
		protocol:  connection.HTTP2,
		connIndex: 1,
		version:   "unknown",
		rootCAs:   trust.Pool(),
		interval:  DefaultInterval,
		log:       &nop,
		gone:      func() {},
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

// WithHostname sets the tunnel's public hostname, checked before any dial;
// a :port suffix is ignored.
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

// WithProtocol sets the transport Probe asks over. Default http2. A selector
// (WithProtocolSelector) takes precedence when set.
func (p *Prober) WithProtocol(protocol connection.Protocol) *Prober {
	p.protocol = protocol
	return p
}

// WithProtocolSelector sets the connector's selector, read per probe:
// cloudflared falls back at runtime, and probing the transport it abandoned
// would ask over a path this network may not carry.
func (p *Prober) WithProtocolSelector(selector connection.ProtocolSelector) *Prober {
	if selector != nil {
		p.protocolSelector = selector
	}
	return p
}

// WithConnIndex sets the connection index the probe registers under. It must
// sit clear of the connector's own: registering an index already in use
// answers EDUPCONN, which says the tunnel exists but is a slower way to hear
// it. Default 1.
func (p *Prober) WithConnIndex(index uint8) *Prober {
	p.connIndex = index
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

// WithInterval sets how often Run asks.
func (p *Prober) WithInterval(interval time.Duration) *Prober {
	if interval > 0 {
		p.interval = interval
	}
	return p
}

// OnGone sets what a positive answer calls, each time.
func (p *Prober) OnGone(fn func()) *Prober {
	if fn != nil {
		p.gone = fn
	}
	return p
}

// Run probes on the interval until ctx ends. It blocks; run it on its own
// goroutine. A slow probe delays the next tick rather than stacking on top
// of it: a ticker holds at most one pending tick.
func (p *Prober) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			switch err := p.Probe(context.WithTimeout(ctx, Timeout)); {
			case errors.Is(err, ErrGone):
				p.log.Info().Err(err).Msg("tunnel is gone")
				p.gone()
			case errors.Is(err, ErrInUse):
				// Another prober on the same index, most likely. Transient,
				// and not the question this asks.
				p.log.Debug().Err(err).Msg("probe index in use")
			case err != nil:
				p.log.Debug().Err(err).Msg("probe got no answer")
			}
		}
	}
}

// ErrGone is Probe's answer when the tunnel no longer exists. ErrInUse is
// its answer when the tunnel exists and another connector holds the index
// the probe registered under: the edge refused the registration as a
// duplicate, which says nothing about the tunnel and everything about who
// else is on it.
var (
	ErrGone  = errors.New("tunnel is gone")
	ErrInUse = errors.New("tunnel in use")
)

// Probe asks the edge whether the tunnel still exists: nil when it does and
// the index was free, ErrGone when it does not, ErrInUse when another
// connector holds the index, and the reason when it could not ask. It asks
// over the selector's current protocol when one is set, else the fixed one.
// ctx bounds the whole ask and cancel releases it when the ask is over, so a
// caller passes context.WithTimeout's pair straight through; Run gives each
// of its probes Timeout.
func (p *Prober) Probe(ctx context.Context, cancel context.CancelFunc) error {
	defer cancel()

	// The cheap answer first. A provider that reaps a tunnel deletes the DNS
	// record with it, so a hostname that has stopped existing settles the
	// question without dialing anything.
	//
	// Only NXDOMAIN counts. A SERVFAIL, a timeout, or every endpoint being
	// unreachable is a question that went unanswered, not an answer. It is a
	// supporting signal, not the arbiter: the registration below asks the
	// edge the same question. This one gets there without a handshake when
	// the record is already gone — and catches what the handshake cannot, a
	// tunnel that still exists behind a name nothing can reach.
	if p.hostname != "" {
		host := p.hostname
		if h, _, err := net.SplitHostPort(p.hostname); err == nil {
			host = h
		}
		for _, resolver := range p.dohResolvers() {
			if ctx.Err() != nil {
				break
			}
			lookup, cancel := context.WithTimeout(ctx, dohTimeout)
			_, err := resolver.LookupHost(lookup, host)
			cancel()

			// The first endpoint to answer at all decides. These are
			// independent operators, so disagreement is not something to
			// arbitrate, and a second opinion on a positive NXDOMAIN would
			// only slow the common case where the name is simply still there.
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				return fmt.Errorf("%w: %s no longer resolves", ErrGone, host)
			}
			if err == nil {
				break
			}
		}
	}

	protocol := p.protocol
	if p.protocolSelector != nil {
		protocol = p.protocolSelector.Current()
	}
	var err error
	switch protocol {
	case connection.QUIC:
		err = p.registerOverQUIC(ctx)
	case connection.HTTP2:
		err = p.registerOverHTTP2(ctx)
	default:
		return fmt.Errorf("no registration path for %s", protocol)
	}
	if err != nil {
		// cloudflared surfaces a refused registration as prose, so this is the
		// same string match its own supervisor makes.
		msg := err.Error()
		switch {
		case strings.Contains(msg, "Unauthorized") || strings.Contains(msg, "Tunnel not found"):
			return fmt.Errorf("%w: edge refused the connection: %w", ErrGone, err)
		case strings.Contains(msg, connection.DuplicateConnectionError):
			return fmt.Errorf("%w: index %d: %w", ErrInUse, p.connIndex, err)
		}
		return fmt.Errorf("no answer from the edge over %s: %w", protocol, err)
	}
	p.log.Debug().Str("protocol", protocol.String()).Msg("edge accepted the connection, tunnel still exists")
	return nil
}

// LookupHost resolves host through the DoH resolvers, first to answer wins.
// The machine's resolver is never asked.
func (p *Prober) LookupHost(ctx context.Context, host string) (string, error) {
	var lastErr error
	for _, resolver := range p.dohResolvers() {
		if ctx.Err() != nil {
			return "", ctx.Err()
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
	return "", lastErr
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

// anEdgeConn walks the discovery pool and returns the first connection dial
// manages to make, rather than the first address it finds: discovery yields
// twenty-odd addresses per region and any one can be unreachable while the
// edge as a whole is fine. Attempts are bounded by ctx rather than counted.
func anEdgeConn[T any](ctx context.Context, log *zerolog.Logger, dial func(*allregions.EdgeAddr) (T, error)) (T, error) {
	var none T
	regions, err := allregions.EdgeDiscovery(log, edgeSRVService)
	if err != nil {
		return none, fmt.Errorf("edge discovery: %w", err)
	}

	var tried int
	var lastErr error
	for _, region := range regions {
		for _, edge := range region {
			conn, err := dial(edge)
			if err == nil {
				return conn, nil
			}
			tried++
			lastErr = err
			log.Debug().Err(err).Msg("edge address did not answer")

			if ctx.Err() != nil {
				return none, fmt.Errorf("no edge answered in %d attempts: %w", tried, ctx.Err())
			}
		}
	}
	if lastErr == nil {
		return none, errors.New("edge discovery returned no usable addresses")
	}
	return none, fmt.Errorf("no edge answered in %d attempts: %w", tried, lastErr)
}

// tlsConfig is the edge TLS config for protocol, carrying the trust set.
func (p *Prober) tlsConfig(protocol connection.Protocol) (*tls.Config, error) {
	settings := protocol.TLSSettings()
	if settings == nil {
		return nil, fmt.Errorf("no TLS settings for %s", protocol)
	}
	return crypto.TLSConfigWithCurvePreferences(&tls.Config{
		ServerName: settings.ServerName,
		NextProtos: settings.NextProtos,
		RootCAs:    p.rootCAs,
	}, features.PostQuantumPrefer)
}

// register runs one registration over rw and returns what the edge answers.
// A refusal is the point; success just means the tunnel is there.
func (p *Prober) register(ctx context.Context, rw io.ReadWriteCloser, edgeIP net.IP) error {
	tunnelID, err := uuid.Parse(p.id)
	if err != nil {
		return fmt.Errorf("invalid tunnel id: %w", err)
	}
	client := tunnelrpc.NewRegistrationClient(ctx, rw, Timeout)
	defer client.Close()

	// A real UUID: the edge validates the client id before it looks at the
	// credentials, so an empty one is refused for the wrong reason.
	id := uuid.New()
	auth := pogs.TunnelAuth{AccountTag: p.accountTag, TunnelSecret: p.secret}
	reg, err := client.RegisterConnection(ctx, auth, tunnelID, &pogs.ConnectionOptions{
		Client: pogs.ClientInfo{
			ClientID: id[:],
			Version:  p.version,
			Arch:     runtime.GOOS + "_" + runtime.GOARCH,
		},
	}, p.connIndex, edgeIP)

	p.log.Debug().Any("reg", reg).Err(err).Msg("registration result")
	if err != nil {
		return err
	}
	if err := client.GracefulShutdown(ctx, time.Second); err != nil {
		p.log.Debug().Err(err).Msg("edge did not acknowledge the probe leaving")
	}
	return nil
}

// registerOverQUIC opens a stream to the edge and registers on it. cloudflared
// opens the control stream on QUIC, so the probe drives the whole exchange.
func (p *Prober) registerOverQUIC(ctx context.Context) error {
	tlsConfig, err := p.tlsConfig(connection.QUIC)
	if err != nil {
		return err
	}
	quicConfig := &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		MaxIdleTimeout:       idleTimeout,
		// Cloudflared's 1s, comfortably inside the idle timeout so
		// the connection survives the pause between dialing and the
		// registration round trip.
		KeepAlivePeriod: cfquic.MaxIdlePingPeriod,
	}

	var edgeIP net.IP
	conn, err := anEdgeConn(ctx, p.log, func(edge *allregions.EdgeAddr) (cfquic.QUICConnection, error) {
		if edge.UDP == nil {
			return nil, errors.New("edge address has no UDP endpoint")
		}
		ip, ok := netip.AddrFromSlice(edge.UDP.IP)
		if !ok {
			return nil, errors.New("edge address has an unusable UDP IP")
		}
		// nolint: gosec // a port is uint16 by definition
		addr := netip.AddrPortFrom(ip.Unmap(), uint16(edge.UDP.Port))
		conn, err := connection.DialQuic(ctx, quicConfig, tlsConfig, addr, nil, p.connIndex, p.log,
			// A probe must not share the connector's UDP port.
			dialopts.DialOpts{SkipPortReuse: true})
		if err == nil {
			edgeIP = edge.UDP.IP
		}
		return conn, err
	})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "probe complete")

	// The edge takes the first stream on a connection as the control
	// plane.
	stream, err := conn.OpenStream()
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}
	defer stream.Close()

	return p.register(ctx, stream, edgeIP)
}

// registerOverHTTP2 answers the edge's control stream and registers on it.
// The roles are reversed from QUIC: cloudflared dials TCP, serves HTTP/2 on
// the socket, and the edge opens the control stream by requesting it, so the
// probe stands up a server and waits to be asked.
func (p *Prober) registerOverHTTP2(ctx context.Context) error {
	tlsConfig, err := p.tlsConfig(connection.HTTP2)
	if err != nil {
		return err
	}

	var edgeIP net.IP
	conn, err := anEdgeConn(ctx, p.log, func(edge *allregions.EdgeAddr) (net.Conn, error) {
		if edge.TCP == nil {
			return nil, errors.New("edge address has no TCP endpoint")
		}
		conn, err := edgediscovery.DialEdge(ctx, handshakeTimeout, tlsConfig, edge.TCP, nil)
		if err == nil {
			edgeIP = edge.TCP.IP
		}
		return conn, err
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	// Buffered, so the handler can finish even when ctx wins the race
	// below.
	answered := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(connection.InternalUpgradeHeader) != connection.ControlStreamUpgrade {
			return
		}
		rw, err := connection.NewHTTP2RespWriter(r, w, connection.TypeControlStream, p.log)
		if err != nil {
			answered <- err
			return
		}
		answered <- p.register(r.Context(), rw, edgeIP)
	})
	go (&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Context: ctx, Handler: handler})

	select {
	case err := <-answered:
		return err
	case <-ctx.Done():
		return fmt.Errorf("edge opened no control stream: %w", ctx.Err())
	}
}
