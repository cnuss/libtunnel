package cloudflare

import (
	"context"
	"crypto/tls"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/connection/dialopts"
	cfdcrypto "github.com/cloudflare/cloudflared/crypto"
	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
	"github.com/cloudflare/cloudflared/features"
	quicpogs "github.com/cloudflare/cloudflared/quic"
	"github.com/cloudflare/cloudflared/tunnelrpc"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"

	v1 "github.com/cnuss/libtunnel/v1"
)

// goneSettle is how long the edge must stay down before the probe runs.
// cloudflared retries forever, so a tunnel down for a moment is reconnecting
// and one down for longer is worth asking about — and asking costs a
// registration, so the delay is what stops a flapping edge from spending one
// per attempt.
//
// #182 measured a client noticing a deleted tunnel at 12s over QUIC and 188s
// over http2, which brackets the useful range: shorter than either, and the
// probe is what finds out rather than a straggling log line.
const goneSettle = 10 * time.Second

// goneProbeTimeout bounds one probe end to end — discovery, dial, handshake,
// RPC. Past it the answer is "unknown", never "gone".
const goneProbeTimeout = 15 * time.Second

// probeConnIndex is the connection index the probe registers under. The
// supervisor owns 0..haConnections-1, so this sits clear: registering an index
// already in use answers EDUPCONN, which is a usable answer but a slower way
// to reach one.
const probeConnIndex = haConnections

// edgeSRVService is the SRV service cloudflared discovers the edge through.
const edgeSRVService = "v2-origintunneld"

// goneWatch arms the probe when the edge goes quiet and disarms it when a
// connection comes back, so a probe runs once per outage rather than once per
// disconnect — the supervisor emits one of those per serve attempt.
type goneWatch struct {
	mu    sync.Mutex
	timer *time.Timer
	fired bool
}

// down starts the settle clock. A connection returning before it expires
// cancels the probe entirely.
func (g *goneWatch) down(probe func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fired {
		return
	}
	if g.timer != nil {
		g.timer.Stop()
	}
	g.timer = time.AfterFunc(goneSettle, func() {
		g.mu.Lock()
		if g.fired {
			g.mu.Unlock()
			return
		}
		g.fired = true
		g.mu.Unlock()
		probe()
	})
}

// up cancels a pending probe: the edge answered, so there is nothing to ask.
func (g *goneWatch) up() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}
}

// stop releases the timer for good.
func (g *goneWatch) stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.timer != nil {
		g.timer.Stop()
		g.timer = nil
	}
	g.fired = true
}

// tunnelGone asks the edge whether spec's tunnel still exists, by doing what
// the connector does — dial, open the control stream, register — and reading
// the answer RegisterConnection returns rather than one cloudflared logged.
//
// It reports (gone, known). Only the edge answering sets known: anything that
// fails before it speaks is a network problem, and a network problem is not
// evidence about a tunnel.
func tunnelGone(ctx context.Context, spec *Spec, log *zerolog.Logger) (gone, known bool) {
	ctx, cancel := context.WithTimeout(ctx, goneProbeTimeout)
	defer cancel()

	tunnelID, err := uuid.Parse(spec.ID)
	if err != nil {
		return false, false
	}
	addr, ok := anEdgeAddr(log)
	if !ok {
		return false, false
	}

	settings := connection.QUIC.TLSSettings()
	tlsConfig, err := cfdcrypto.TLSConfigWithCurvePreferences(&tls.Config{
		ServerName: settings.ServerName,
		NextProtos: settings.NextProtos,
		RootCAs:    caCertPool(),
	}, features.PostQuantumPrefer)
	if err != nil {
		return false, false
	}

	conn, err := connection.DialQuic(ctx, &quic.Config{
		HandshakeIdleTimeout: quicpogs.HandshakeIdleTimeout,
		MaxIdleTimeout:       quicpogs.MaxIdleTimeout,
		KeepAlivePeriod:      quicpogs.MaxIdlePingPeriod,
	}, tlsConfig, addr, nil, probeConnIndex, log,
		// A probe must not share the connector's UDP port; cloudflared offers
		// this flag for exactly that.
		dialopts.DialOpts{SkipPortReuse: true})
	if err != nil {
		return false, false
	}
	defer conn.CloseWithError(0, "probe complete")

	// The edge takes the first stream on a connection as the control plane.
	stream, err := conn.OpenStream()
	if err != nil {
		return false, false
	}
	defer stream.Close()

	client := tunnelrpc.NewRegistrationClient(ctx, stream, goneProbeTimeout)
	defer client.Close()

	_, err = client.RegisterConnection(ctx,
		pogs.TunnelAuth{AccountTag: spec.AccountTag, TunnelSecret: spec.Secret},
		tunnelID, probeOptions(), probeConnIndex, addr.Addr().AsSlice())
	switch {
	case err == nil:
		// It registered, so the tunnel exists. Unregister at once: the edge
		// would otherwise route to a connection with no origin behind it.
		_ = client.GracefulShutdown(ctx, time.Second)
		return false, true
	case err.Error() == connection.DuplicateConnectionError:
		// Only something already registered can hold the index.
		return false, true
	case registrationRefused(err):
		return true, true
	default:
		// The edge said something this build does not recognize. Not evidence
		// either way, and worth seeing: the classification above is the whole
		// mechanism, and this is where it comes up short.
		log.Debug().Err(err).Msg("gone probe: unclassified answer from the edge")
		return false, false
	}
}

// probeOptions is the connection description the probe registers with. The
// client id has to be a real UUID — the edge rejects an empty one with
// "invalid client ID, cannot convert into UUID" *after* it has checked the
// credentials, so an unpopulated one turns a definite answer into a confusing
// one on tunnels that do exist.
//
// It is a fresh id each time, deliberately: the probe is not the connector and
// should not claim to be the same client.
func probeOptions() *pogs.ConnectionOptions {
	id := uuid.New()
	return &pogs.ConnectionOptions{
		Client: pogs.ClientInfo{
			ClientID: id[:],
			Version:  cloudflaredVersion,
			Arch:     runtime.GOOS + "_" + runtime.GOARCH,
		},
	}
}

// registrationRefused reports whether err is the edge saying this is not a
// tunnel it knows.
//
// A string test, because the RPC hands back the server's message as a plain
// error and #182 established there is nothing better. Unlike the log scraping
// it replaces, this reads the return value of the call that asked the
// question, so nothing else can land in it — a proxied origin's 401 has no
// path here.
func registrationRefused(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "Unauthorized") || strings.Contains(msg, "Tunnel not found")
}

// anEdgeAddr resolves one edge address to probe, through cloudflared's own
// discovery so the probe reaches the edge the connector would.
func anEdgeAddr(log *zerolog.Logger) (netip.AddrPort, bool) {
	regions, err := allregions.EdgeDiscovery(log, edgeSRVService)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for _, region := range regions {
		for _, addr := range region {
			if addr.UDP == nil {
				continue
			}
			ip, ok := netip.AddrFromSlice(addr.UDP.IP)
			if !ok {
				continue
			}
			// nolint: gosec // a port is uint16 by definition
			return netip.AddrPortFrom(ip.Unmap(), uint16(addr.UDP.Port)), true
		}
	}
	return netip.AddrPort{}, false
}

// emitter is the half of the tunnel the probe needs: somewhere to report.
type emitter interface{ Emit(v1.Event) }
