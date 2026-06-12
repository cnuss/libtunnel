// Package cloudflare is the Cloudflare backend for libtunnel: a cloudflared
// quick-tunnel engine driven entirely in-process (no cloudflared binary). It
// implements the v1alpha1 Engine contract; obtain it through the façade
// constructor libtunnel.Cloudflare().
package cloudflare

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/breml/rootcerts/embedded"
	"github.com/cloudflare/cloudflared/client"
	"github.com/cloudflare/cloudflared/config"
	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/edgediscovery"
	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
	"github.com/cloudflare/cloudflared/features"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/ingress/origins"
	"github.com/cloudflare/cloudflared/orchestration"
	"github.com/cloudflare/cloudflared/signal"
	"github.com/cloudflare/cloudflared/supervisor"
	"github.com/cloudflare/cloudflared/tlsconfig"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// cloudflaredVersion is reported to the edge as the connector version —
// inferred from the cloudflared module in the build info so it tracks go.mod
// instead of drifting in a hand-maintained constant.
var cloudflaredVersion = func() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/cloudflare/cloudflared" {
				return dep.Version
			}
		}
	}
	return "unknown"
}()

// promMu serializes the prometheus.DefaultRegisterer swap below: cloudflared
// registers metrics against the global registerer at construction, which
// would collide across tunnels (and pollute the host application's metrics).
var promMu sync.Mutex

// Backend is the cloudflared quick-tunnel engine. Stateless; one value can
// serve any number of tunnels.
type Backend struct{}

// New returns the Cloudflare backend.
func New() *Backend {
	return &Backend{}
}

var (
	_ v1.Backend[*Spec]      = (*Backend)(nil)
	_ v1alpha1.Engine[*Spec] = (*Backend)(nil)
	// One TunnelImpl serves both phases of the v1 contract.
	_ v1.Tunnel[*Spec]    = (*v1alpha1.TunnelImpl[*Spec])(nil)
	_ v1.Connected[*Spec] = (*v1alpha1.TunnelImpl[*Spec])(nil)
)

// Name implements v1.Backend.
func (b *Backend) Name() string {
	return "cloudflare"
}

// Provider is the Cloudflare credential chain: adopt TUNNEL_SPEC from the
// environment when a parent process handed one off, otherwise mint an
// anonymous quick tunnel from api.trycloudflare.com. Mutators for named
// tunnels / other endpoints will hang off Cloudflare() when they exist.
func (b *Backend) Provider() v1.Provider[*Spec] {
	return v1alpha1.Env(b.Name(), QuickTunnel())
}

// caCerts parses the trust set once per process: the Mozilla bundle is a
// compile-time constant and the Cloudflare roots are fixed, so re-parsing
// ~150 certificates per tunnel was pure waste.
var caCerts = sync.OnceValue(func() []*x509.Certificate {
	certificates := []*x509.Certificate{}

	rest := []byte(embedded.MozillaCACertificatesPEM())
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remainder
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certificates = append(certificates, cert)
		}
	}

	cloudflareRoots, _ := tlsconfig.GetCloudflareRootCA()
	return append(certificates, cloudflareRoots...)
})

// CACerts returns the Mozilla CA bundle plus the Cloudflare origin roots —
// the trust set cloudflared uses for its edge TLS connections.
func (b *Backend) CACerts() []*x509.Certificate {
	return caCerts()
}

// WithListener dials the Cloudflare edge and proxies it onto l. It blocks
// until the first edge connection is up; the supervisor keeps running in the
// background for the tunnel's lifetime, reporting fatal errors through
// t.Cancel.
func (b *Backend) WithListener(t *v1alpha1.TunnelImpl[*Spec], l net.Listener) error {
	ctx := t.Context()
	log := zerologger(t.Logger())
	spec := t.Spec()
	if spec == nil {
		return fmt.Errorf("no spec resolved")
	}
	tunnelID, err := uuid.Parse(spec.ID)
	if err != nil {
		return fmt.Errorf("invalid tunnel id %q in spec: %w", spec.ID, err)
	}

	// quic-go logs a buffer-size warning straight to the global log package
	// (bypassing any configured logger) when the kernel caps its 7 MB UDP
	// buffer request — a throughput note, not an error. Suppress it unless
	// the host explicitly opted in to seeing it.
	if _, set := os.LookupEnv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING"); !set {
		os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	}

	// The closure scopes the prometheus.DefaultRegisterer swap to supervisor
	// construction: cloudflared registers collectors against the global
	// registerer at construction, which would collide across tunnels and
	// pollute the host application's metrics, so it is pointed at a noop
	// (under promMu) and restored by defer when construction finishes. The
	// supervisor's run and the (unbounded) wait for the first edge connection
	// happen below, outside the lock, so concurrent tunnels neither serialize
	// behind one tunnel's connect nor discard the host's own registrations in
	// the meantime.
	sup, err := func() (*supervisor.Supervisor, error) {
		promMu.Lock()
		defer promMu.Unlock()
		registerer := prometheus.DefaultRegisterer
		prometheus.DefaultRegisterer = noop()
		defer func() { prometheus.DefaultRegisterer = registerer }()

		featureSelector, err := features.NewFeatureSelector(ctx, spec.AccountTag, nil, false, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create feature selector: %w", err)
		}
		clientConfig, err := client.NewConfig(cloudflaredVersion, fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH), featureSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to create client config: %w", err)
		}
		protocolSelector, err := connection.NewProtocolSelector("auto", spec.AccountTag, false, edgediscovery.ProtocolPercentage, connection.ResolveTTL, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create protocol selector: %w", err)
		}

		originDialer := ingress.NewOriginDialer(ingress.OriginConfig{}, log)

		tunnelConfig := &supervisor.TunnelConfig{
			ClientConfig: clientConfig,
			// cloudflared's own default (its --grace-period flag): how long the
			// supervisor waits for in-flight requests on graceful shutdown — and
			// ctx.Done is wired as the graceful-shutdown signal below, so this
			// bounds teardown after a cancel. Max accepted is 3m.
			GracePeriod:   30 * time.Second,
			Region:        "",
			EdgeIPVersion: allregions.Auto,
			HAConnections: 1,
			// No tags, matching cloudflared's quick-tunnel default. (Tags never
			// were the connector ID — client.NewConfig mints a fresh random UUID
			// for that; tags only become Cf-Warp-Tag-* headers injected into
			// every request hitting the origin.)
			Tags:            nil,
			Log:             log,
			LogTransport:    log,
			Observer:        connection.NewObserver(log, log),
			ReportedVersion: cloudflaredVersion,
			Retries:         5,
			RunFromTerminal: false,
			NamedTunnel: &connection.TunnelProperties{
				Credentials: connection.Credentials{
					AccountTag:   spec.AccountTag,
					TunnelSecret: spec.Secret,
					TunnelID:     tunnelID,
				},
				QuickTunnelUrl: t.Hostname(),
			},
			ProtocolSelector: protocolSelector,
			EdgeTLSConfigs: func() map[connection.Protocol]*tls.Config {
				pool := x509.NewCertPool()
				for _, c := range t.CACerts() {
					pool.AddCert(c)
				}
				out := make(map[connection.Protocol]*tls.Config, len(connection.ProtocolList))
				for _, p := range connection.ProtocolList {
					s := p.TLSSettings()
					out[p] = &tls.Config{ServerName: s.ServerName, NextProtos: s.NextProtos, RootCAs: pool}
				}
				return out
			}(),
			MaxEdgeAddrRetries:  8,
			RPCTimeout:          5 * time.Second,
			OriginDNSService:    origins.NewDNSResolverService(originDialer, log, noop()),
			OriginDialerService: originDialer,
		}

		// The origin scheme follows the listener: a TLS listener gets an https
		// ingress (self-signed is fine — verification is off), a plain one gets
		// http.
		tlsOrigin := v1alpha1.IsTLS(l)
		scheme := "http"
		if tlsOrigin {
			scheme = "https"
		}

		noTLSVerify := true
		internalRules := []ingress.Rule{}
		parsed, err := ingress.ParseIngress(&config.Configuration{
			OriginRequest: config.OriginRequestConfig{
				NoTLSVerify: &noTLSVerify,
				Http2Origin: &tlsOrigin,
			},
			WarpRouting: config.WarpRoutingConfig{},
			Ingress: []config.UnvalidatedIngressRule{
				{Service: fmt.Sprintf("%s://%s", scheme, l.Addr().String())},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to parse ingress for %s://%s: %w", scheme, l.Addr().String(), err)
		}
		orchestrator, err := orchestration.NewOrchestrator(ctx, &orchestration.Config{
			Ingress:             &parsed,
			WarpRouting:         ingress.NewWarpRoutingConfig(&config.WarpRoutingConfig{}), // cloudflared defaults: 5s connect, unlimited flows, 30s keepalive
			OriginDialerService: originDialer,
			ConfigurationFlags:  map[string]string{}, // CLI-flag overrides for remote config; empty matches cloudflared quick-tunnel behavior
		}, tunnelConfig.Tags, internalRules, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create orchestrator: %w", err)
		}

		// Nothing here produces manual reconnect signals; the channel only
		// exists to satisfy NewSupervisor, which selects on it.
		reconnected := make(chan supervisor.ReconnectSignal)
		sup, err := supervisor.NewSupervisor(tunnelConfig, orchestrator, reconnected, ctx.Done())
		if err != nil {
			return nil, fmt.Errorf("failed to create supervisor: %w", err)
		}
		return sup, nil
	}()
	if err != nil {
		return err
	}

	connected := signal.New(make(chan struct{}))
	go func() {
		if err := sup.Run(ctx, connected); err != nil {
			t.Cancel(fmt.Errorf("supervisor run failed: %w", err))
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connected.Wait():
	}
	return nil
}

// noopImpl satisfies the metrics interfaces cloudflared insists on with
// do-nothing implementations.
type noopImpl struct {
	origins.Metrics
	prometheus.Registerer
}

var (
	_ origins.Metrics       = (*noopImpl)(nil)
	_ prometheus.Registerer = (*noopImpl)(nil)
)

func noop() *noopImpl {
	return &noopImpl{}
}

func (n *noopImpl) IncrementDNSTCPRequests() {}
func (n *noopImpl) IncrementDNSUDPRequests() {}

func (n *noopImpl) Register(prometheus.Collector) error  { return nil }
func (n *noopImpl) MustRegister(...prometheus.Collector) {}
func (n *noopImpl) Unregister(prometheus.Collector) bool { return true }
