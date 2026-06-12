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
	"runtime"
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
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// cloudflaredVersion is reported to the edge as the connector version.
const cloudflaredVersion = "2026.3.0"

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

var _ v1alpha1.Engine[*v1.CloudflareSpec] = (*Backend)(nil)

// Name implements v1.Backend.
func (b *Backend) Name() string {
	return "cloudflare"
}

// CACerts returns the Mozilla CA bundle plus the Cloudflare origin roots —
// the trust set cloudflared uses for its edge TLS connections.
func (b *Backend) CACerts() []*x509.Certificate {
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
	certificates = append(certificates, cloudflareRoots...)

	return certificates
}

// WithListener dials the Cloudflare edge and proxies it onto l. It blocks
// until the first edge connection is up; the supervisor keeps running in the
// background for the tunnel's lifetime, reporting fatal errors through
// t.Cancel.
func (b *Backend) WithListener(t *v1alpha1.TunnelImpl[*v1.CloudflareSpec], l net.Listener) error {
	ctx := t.Context()
	log := zerologger(t.Logger())
	spec := t.Spec()
	if spec == nil {
		return fmt.Errorf("no spec resolved")
	}

	// cloudflared registers collectors against the global default registerer;
	// point it at a noop for the construction window so concurrent tunnels
	// don't collide and the host application's metrics stay clean.
	promMu.Lock()
	defer promMu.Unlock()
	registerer := prometheus.DefaultRegisterer
	prometheus.DefaultRegisterer = noop()
	defer func() { prometheus.DefaultRegisterer = registerer }()

	originDialer := ingress.NewOriginDialer(ingress.OriginConfig{}, log)

	tunnelConfig := &supervisor.TunnelConfig{
		ClientConfig: func() *client.Config {
			featureSelector, _ := features.NewFeatureSelector(ctx, spec.AccountTag, nil, false, log)
			cfg, _ := client.NewConfig(cloudflaredVersion, fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH), featureSelector)
			return cfg
		}(),
		GracePeriod:     60 * time.Second, // TODO(partial): what is a good default here?
		Region:          "",
		EdgeIPVersion:   allregions.Auto,
		HAConnections:   1,
		Tags:            []pogs.Tag{{Name: "ID", Value: spec.ID}}, // TODO(experimental): reuse tunnel ID as connector ID; cloudflared normally generates a fresh UUID per process
		Log:             log,
		LogTransport:    log,
		Observer:        connection.NewObserver(log, log),
		ReportedVersion: cloudflaredVersion,
		Retries:         5,
		RunFromTerminal: false,
		NamedTunnel: func() *connection.TunnelProperties {
			tunnelID, _ := uuid.Parse(spec.ID)
			return &connection.TunnelProperties{
				Credentials: connection.Credentials{
					AccountTag:   spec.AccountTag,
					TunnelSecret: spec.Secret,
					TunnelID:     tunnelID,
				},
				QuickTunnelUrl: t.Hostname(),
			}
		}(),
		ProtocolSelector: func() connection.ProtocolSelector {
			protocolSelector, _ := connection.NewProtocolSelector("auto", spec.AccountTag, false, false, edgediscovery.ProtocolPercentage, connection.ResolveTTL, log)
			return protocolSelector
		}(),
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

	noTLSVerify := true
	http2Origin := true
	internalRules := []ingress.Rule{}
	orchestrator, err := orchestration.NewOrchestrator(ctx, &orchestration.Config{
		Ingress: func() *ingress.Ingress {
			parsed, _ := ingress.ParseIngress(&config.Configuration{
				OriginRequest: config.OriginRequestConfig{
					NoTLSVerify: &noTLSVerify,
					Http2Origin: &http2Origin,
				},
				WarpRouting: config.WarpRoutingConfig{},
				Ingress: []config.UnvalidatedIngressRule{
					{Service: fmt.Sprintf("https://%s", l.Addr().String())},
				},
			})
			return &parsed
		}(),
		WarpRouting:         ingress.NewWarpRoutingConfig(&config.WarpRoutingConfig{}), // cloudflared defaults: 5s connect, unlimited flows, 30s keepalive
		OriginDialerService: originDialer,
		ConfigurationFlags:  map[string]string{}, // CLI-flag overrides for remote config; empty matches cloudflared quick-tunnel behavior
	}, tunnelConfig.Tags, internalRules, log)
	if err != nil {
		return fmt.Errorf("failed to create orchestrator: %w", err)
	}

	connected := signal.New(make(chan struct{}))
	reconnected := make(chan supervisor.ReconnectSignal) // TODO(partial): what to do with reconnected
	sup, err := supervisor.NewSupervisor(tunnelConfig, orchestrator, reconnected, ctx.Done())
	if err != nil {
		return fmt.Errorf("failed to create supervisor: %w", err)
	}

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

func noop() *noopImpl {
	return &noopImpl{}
}

func (n *noopImpl) IncrementDNSTCPRequests() {}
func (n *noopImpl) IncrementDNSUDPRequests() {}

func (n *noopImpl) Register(prometheus.Collector) error  { return nil }
func (n *noopImpl) MustRegister(...prometheus.Collector) {}
func (n *noopImpl) Unregister(prometheus.Collector) bool { return true }
