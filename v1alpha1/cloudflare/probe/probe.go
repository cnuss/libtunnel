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
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/connection/dialopts"
	"github.com/cloudflare/cloudflared/crypto"
	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
	"github.com/cloudflare/cloudflared/features"
	cfquic "github.com/cloudflare/cloudflared/quic"
	"github.com/cloudflare/cloudflared/tunnelrpc"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/google/uuid"
	dns "github.com/ncruces/go-dns"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"

	"github.com/cnuss/libtunnel/v1alpha1/cloudflare/trust"
)

// Timeout bounds one probe end to end — discovery, dial, handshake, RPC.
const Timeout = 15 * time.Second

// probeConnIndex is the connection index the probe registers under. It must
// sit clear of the connector's own (0 to haConnections-1): the edge routes
// traffic to a registration on a held index, and the probe closing moments
// later strands it — measured as a five-second run of 530s on a live tunnel.
const probeConnIndex = 2

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
		err := p.probe(ctx)
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

func (p *Prober) probe(ctx context.Context) error {
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

	tlsConfig, err := crypto.TLSConfigWithCurvePreferences(&tls.Config{
		ServerName: connection.QUIC.TLSSettings().ServerName,
		NextProtos: connection.QUIC.TLSSettings().NextProtos,
		RootCAs:    p.rootCAs,
	}, features.PostQuantumPrefer)
	if err != nil {
		return fmt.Errorf("%w: edge TLS config: %w", ErrRetry, err)
	}

	regions, err := allregions.EdgeDiscovery(p.log, edgeSRVService)
	if err != nil {
		return fmt.Errorf("%w: edge discovery: %w", ErrRetry, err)
	}
	edge := func() *net.UDPAddr {
		for _, region := range regions {
			for _, candidate := range region {
				if candidate.UDP != nil && candidate.UDP.IP.To4() != nil {
					return candidate.UDP
				}
			}
		}
		return nil
	}()
	if edge == nil {
		return fmt.Errorf("%w: edge discovery returned no IPv4 UDP endpoint", ErrRetry)
	}

	// Unmapped: DialQuic picks its listen network off the address family,
	// and a 4-in-6 address sends it to udp6 for a v4 edge.
	addr := edge.AddrPort()
	conn, err := connection.DialQuic(ctx, &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       15 * time.Second,
		KeepAlivePeriod:      cfquic.MaxIdlePingPeriod,
		// quic-go's 1280 default doesn't fit a 1280-byte path once the
		// UDP and IP headers are on it, and the Initial packet can't
		// shrink below this floor: a tunnelled default route (WARP,
		// Tailscale) never gets a handshake out. 1232 leaves room for
		// either IP version.
		InitialPacketSize: 1232,
	}, tlsConfig, netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), nil, probeConnIndex, p.log,
		// A probe must not share the connector's UDP port.
		dialopts.DialOpts{SkipPortReuse: true})
	if err != nil {
		return fmt.Errorf("%w: dial %s: %w", ErrRetry, edge, err)
	}
	defer conn.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "probe complete")

	// The edge takes the first stream on a connection as the control plane.
	stream, err := conn.OpenStream()
	if err != nil {
		return fmt.Errorf("%w: open control stream to %s: %w", ErrRetry, edge, err)
	}
	defer stream.Close()

	client := tunnelrpc.NewRegistrationClient(ctx, stream, 5*time.Second)
	defer client.Close()

	// A real UUID: the edge validates the client id before the credentials,
	// so an empty one is refused for the wrong reason.
	clientID := uuid.New()
	details, err := client.RegisterConnection(ctx, pogs.TunnelAuth{
		AccountTag:   p.accountTag,
		TunnelSecret: p.secret,
	}, tunnelID, &pogs.ConnectionOptions{
		Client: pogs.ClientInfo{
			ClientID: clientID[:],
			Version:  p.version,
			Arch:     runtime.GOOS + "_" + runtime.GOARCH,
		},
	}, probeConnIndex, edge.IP)

	if err == nil {
		p.log.Info().Any("details", details).Str("hostname", p.hostname).Msg("probe success")
		return nil
	} else if ctx.Err() != nil {
		// An ask cut short is not an answer: the edge never ruled.
		return fmt.Errorf("%w: registration cut short: %w", ErrRetry, context.Cause(ctx))
	} else if strings.Contains(err.Error(), connection.DuplicateConnectionError) {
		p.log.Info().Msg("duplicate connection detected")
		return fmt.Errorf("%w: index %d: %w", ErrInUse, probeConnIndex, err)
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
		p.log.Debug().Str("host", host).Str("resolved", resolved).
			Msg("edge refused the connection but the hostname still resolves")
		return nil
	} else if errors.Is(err, ErrRetry) {
		return fmt.Errorf("edge refused the connection and %s could not be resolved: %w", host, err)
	} else {
		return fmt.Errorf("%w: edge refused the connection and %s no longer resolves: %w", ErrGone, host, err)
	}
}

// LookupHost resolves host through the DoH resolvers, first to answer wins.
// The machine's resolver is never asked.
//
// Only a name that positively does not exist is an answer. A resolver that
// timed out, refused, or could not be reached at all is a question that went
// unasked, and comes back wrapped in ErrRetry so a caller can tell a record
// that is gone from a resolver having a bad day.
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
