// Package cloudflare is the Cloudflare backend for libtunnel: a cloudflared
// quick-tunnel engine driven entirely in-process (no cloudflared binary). It
// implements the v1alpha1 Engine contract; obtain it through the façade
// constructor libtunnel.Cloudflare().
package cloudflare

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/url"
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

// backendName tags specs minted by this backend (Name, Serialize, the
// LIBTUNNEL_SPEC envelope) — one source of truth so the tag never drifts.
const backendName = "cloudflare"

// Backend is the cloudflared quick-tunnel engine. It carries the origin-scheme
// settings declared via WithTLS / WithHTTP2; obtain a fresh one per tunnel from
// libtunnel.Cloudflare(). Both settings default false, and both can be fixed
// from the environment (LIBTUNNEL_TLS / LIBTUNNEL_HTTP2) — a fixed knob makes
// its mutator a no-op.
type Backend struct {
	tls        bool
	tlsFixed   bool
	http2      bool
	http2Fixed bool
	// envErr is the first unparsable env knob, surfaced at connect: an
	// operator override that can't be honored fails the tunnel loudly instead
	// of being silently ignored.
	envErr error
	// provider, when set, pins the credential chain to a fixed spec (From /
	// libtunnel.From). Nil lets the env chain fall through to minting.
	provider v1.Provider[*Spec]
	// fields carries the spec-field overrides set via WithID and friends,
	// applied by the overlay provider when the spec resolves.
	fields Spec
	// apiURL overrides the quick-tunnel mint endpoint (WithApiURL). Empty
	// means the default; v1.CloudflareAPIURLEnv supersedes either.
	apiURL string
	// chopInterval, when non-nil, sets the wrapped listener's clean-close
	// cadence (edge-flush trigger a) via WithFlushInterval — the shim "chops"
	// the response to force the flush. Nil means off. chopFixed records that
	// LIBTUNNEL__CLOUDFLARE_FLUSH_INTERVAL fixed it, so WithFlushInterval is a
	// no-op (env beats code).
	chopInterval *time.Duration
	chopFixed    bool
}

// New returns the Cloudflare backend. The origin-scheme knobs are fixed from
// the environment here when LIBTUNNEL_TLS / LIBTUNNEL_HTTP2 are set, and the
// streaming-buffer lever when LIBTUNNEL__CLOUDFLARE_FLUSH_INTERVAL is set. The
// first unparsable value wins and is surfaced at connect.
func New() *Backend {
	b := &Backend{}
	b.tls, b.tlsFixed, b.envErr = v1alpha1.EnvBool(v1.TLSEnv)
	if b.envErr == nil {
		b.http2, b.http2Fixed, b.envErr = v1alpha1.EnvBool(v1.HTTP2Env)
	}
	if b.envErr == nil {
		var d time.Duration
		d, b.chopFixed, b.envErr = v1alpha1.EnvDuration(v1.CloudflareFlushIntervalEnv)
		if b.chopFixed && b.envErr == nil {
			b.chopInterval = &d
		}
	}
	return b
}

// From returns a Cloudflare backend pinned to spec: it connects with the
// given credentials instead of minting. It backs libtunnel.From. The pin sits
// at the end of the env chain, so LIBTUNNEL_SPEC and LIBTUNNEL_FROM still
// override it (env beats code).
func From(spec *Spec) *Backend {
	b := New()
	b.provider = v1alpha1.Static(spec)
	return b
}

// WithTLS declares whether the origin terminates TLS (https vs http ingress).
// Default false. A no-op when LIBTUNNEL_TLS fixed the knob from the
// environment. Returns the backend for chaining.
func (b *Backend) WithTLS(tls bool) v1.Backend[*Spec] {
	if !b.tlsFixed {
		b.tls = tls
	}
	return b
}

// WithHTTP2 declares whether the origin is dialed over HTTP/2. Default false.
// A no-op when LIBTUNNEL_HTTP2 fixed the knob from the environment. Returns
// the backend for chaining.
func (b *Backend) WithHTTP2(http2 bool) v1.Backend[*Spec] {
	if !b.http2Fixed {
		b.http2 = http2
	}
	return b
}

// The spec-field setters override individual fields of whatever spec the
// credential chain resolves — adopt, replay, pin, or mint — and a complete
// credential set (id, hostname, account tag, secret) short-circuits the
// resolve entirely. Each is superseded field-by-field by its
// LIBTUNNEL__CLOUDFLARE_* variable (env beats code). They return the concrete
// backend, so chain them before the v1.Backend mutators (WithTLS, WithHTTP2),
// which return the interface.

// WithID overrides the tunnel ID (a UUID). Env mirror: LIBTUNNEL__CLOUDFLARE_ID.
func (b *Backend) WithID(id string) *Backend {
	b.fields.ID = id
	return b
}

// WithName overrides the tunnel name. Env mirror: LIBTUNNEL__CLOUDFLARE_NAME.
func (b *Backend) WithName(name string) *Backend {
	b.fields.Name = name
	return b
}

// WithHostname overrides the public hostname. Env mirror:
// LIBTUNNEL__CLOUDFLARE_HOSTNAME.
func (b *Backend) WithHostname(hostname string) *Backend {
	b.fields.Hostname = hostname
	return b
}

// WithAccountTag overrides the account tag. Env mirror:
// LIBTUNNEL__CLOUDFLARE_ACCOUNT_TAG.
func (b *Backend) WithAccountTag(tag string) *Backend {
	b.fields.AccountTag = tag
	return b
}

// WithSecret overrides the tunnel secret. Env mirror:
// LIBTUNNEL__CLOUDFLARE_SECRET (base64, the JSON []byte encoding).
func (b *Backend) WithSecret(secret []byte) *Backend {
	b.fields.Secret = secret
	return b
}

// WithApiURL overrides the quick-tunnel mint endpoint (default
// https://api.trycloudflare.com/tunnel). Env mirror:
// LIBTUNNEL__CLOUDFLARE_API_URL (env beats code). Only the mint path uses
// it — adopted, replayed, and pinned specs never hit the API.
func (b *Backend) WithApiURL(apiURL string) *Backend {
	b.apiURL = apiURL
	return b
}

// WithFlushInterval bounds streaming-response latency in TIME — the analog of
// httputil.ReverseProxy.FlushInterval for the trycloudflare edge. A quick tunnel
// buffers a chunked 200 response at the edge and only releases it on a clean
// response end (terminal chunk) or once 128 KiB of body accumulates; a slow
// watch stream can otherwise stall unboundedly. This knob interposes a session
// shim between cloudflared and the origin (see wrapped_listener.go): it holds
// ONE origin connection per logical request and ends the downstream response
// cleanly every d — the mechanism "chops" the response — forcing the edge flush,
// while a re-issuing client (the kubectl re-watch shape) reattaches to the same
// origin stream. Per-event delivery latency is then bounded by ~d instead of the
// edge's buffer.
//
// The shim is contract-safe: it never mutates the origin's status, headers, or
// body — it only re-frames the same bytes across successive clean-closed
// responses. Default off (nil): no shim, cloudflared dials the origin directly.
// Setting a positive d engages the shim. Env mirror:
// LIBTUNNEL__CLOUDFLARE_FLUSH_INTERVAL (time.ParseDuration syntax) fixes the
// knob and makes this call a no-op — env beats code. Returns the backend for
// chaining.
func (b *Backend) WithFlushInterval(d time.Duration) *Backend {
	if !b.chopFixed {
		b.chopInterval = &d
	}
	return b
}

var (
	_ v1.Backend[*Spec]      = (*Backend)(nil)
	_ v1alpha1.Engine[*Spec] = (*Backend)(nil)
	_ v1.Tunnel              = (*v1alpha1.TunnelImpl[*Spec])(nil)
)

// Name implements v1.Backend.
func (b *Backend) Name() string {
	return backendName
}

// Provider is the Cloudflare credential chain, env first: adopt
// LIBTUNNEL_SPEC when a parent process handed one off; apply the spec-field
// overrides (WithID and friends plus their LIBTUNNEL__CLOUDFLARE_* mirrors —
// a complete credential set stops here); replay the spec LIBTUNNEL_FROM
// references; then the code-pinned spec (From); and finally mint an anonymous
// quick tunnel from api.trycloudflare.com.
func (b *Backend) Provider() v1.Provider[*Spec] {
	next := b.provider
	if next == nil {
		qt := QuickTunnel()
		qt.URL = b.apiURL
		stringEnv(v1.CloudflareAPIURLEnv, &qt.URL)
		next = qt
	}
	return v1alpha1.Env(b.Name(), overlay{fields: b.fields, next: v1alpha1.Replay(b.Name(), next)})
}

// overlay applies the spec-field overrides: fields (the WithID-family
// setters), each superseded by its LIBTUNNEL__CLOUDFLARE_* variable. A
// complete credential set — id, hostname, account tag, secret — is a spec of
// its own and short-circuits the chain below; a partial one patches whatever
// the chain resolves, non-zero fields only.
type overlay struct {
	fields Spec
	next   v1.Provider[*Spec]
}

// SetLogger forwards the tunnel's logger to the wrapped provider.
func (p overlay) SetLogger(log *slog.Logger) {
	if pl, ok := p.next.(v1alpha1.LoggerSetter); ok {
		pl.SetLogger(log)
	}
}

func (p overlay) Spec(ctx context.Context) (*Spec, error) {
	fields := p.fields
	stringEnv(v1.CloudflareIDEnv, &fields.ID)
	stringEnv(v1.CloudflareNameEnv, &fields.Name)
	stringEnv(v1.CloudflareHostnameEnv, &fields.Hostname)
	stringEnv(v1.CloudflareAccountTagEnv, &fields.AccountTag)
	if v := os.Getenv(v1.CloudflareSecretEnv); v != "" {
		secret, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", v1.CloudflareSecretEnv, err)
		}
		fields.Secret = secret
	}

	if fields.ID != "" && fields.Hostname != "" && fields.AccountTag != "" && len(fields.Secret) > 0 {
		return &fields, nil
	}

	base, err := p.next.Spec(ctx)
	if err != nil {
		return nil, err
	}
	merged := *base
	stringField(fields.ID, &merged.ID)
	stringField(fields.Name, &merged.Name)
	stringField(fields.Hostname, &merged.Hostname)
	stringField(fields.AccountTag, &merged.AccountTag)
	if len(fields.Secret) > 0 {
		merged.Secret = fields.Secret
	}
	return &merged, nil
}

// stringEnv overwrites *field with the env variable's value when it is set
// and non-empty.
func stringEnv(name string, field *string) {
	if v := os.Getenv(name); v != "" {
		*field = v
	}
}

// stringField overwrites *field with override when the override is non-zero.
func stringField(override string, field *string) {
	if override != "" {
		*field = override
	}
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
// t.Cancel. The origin scheme follows the backend's explicit WithTLS setting
// (default false ⇒ http).
func (b *Backend) WithListener(t *v1alpha1.TunnelImpl[*Spec], l net.Listener) error {
	scheme := "http"
	if b.tls {
		scheme = "https"
	}
	return b.connect(t, fmt.Sprintf("%s://%s", scheme, l.Addr().String()))
}

// WithLocalURL dials the Cloudflare edge and proxies it onto an
// already-running local origin. The URL arrives validated and reduced to
// scheme+host by the core, so its scheme — not WithTLS — declares how the
// origin is dialed.
func (b *Backend) WithLocalURL(t *v1alpha1.TunnelImpl[*Spec], u *url.URL) error {
	return b.connect(t, fmt.Sprintf("%s://%s", u.Scheme, u.Host))
}

// connect is the shared engine body behind WithListener and WithLocalURL:
// service is the cloudflared ingress service URL the edge proxies to.
func (b *Backend) connect(t *v1alpha1.TunnelImpl[*Spec], service string) error {
	if b.envErr != nil {
		return b.envErr
	}
	// The flush-interval lever engages the session shim; unset, the origin is
	// dialed directly (path untouched).
	if b.chopInterval != nil {
		u, err := url.Parse(service)
		if err != nil {
			return fmt.Errorf("wrapped listener: %w", err)
		}
		wl, err := newWrappedListener(t.Context(), t.Logger(), u.Host, *b.chopInterval)
		if err != nil {
			return fmt.Errorf("wrapped listener: %w", err)
		}
		u.Host = wl.Addr().String()
		service = u.String()
	}
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

		// HTTP/2 follows the backend's explicit WithHTTP2 setting (default
		// false); the service URL's scheme picks https vs http. TLS
		// verification is always off — a local origin may carry a self-signed
		// cert.
		noTLSVerify := true
		http2Origin := b.http2

		internalRules := []ingress.Rule{}
		parsed, err := ingress.ParseIngress(&config.Configuration{
			OriginRequest: config.OriginRequestConfig{
				NoTLSVerify: &noTLSVerify,
				Http2Origin: &http2Origin,
			},
			WarpRouting: config.WarpRoutingConfig{},
			Ingress: []config.UnvalidatedIngressRule{
				{Service: service},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to parse ingress for %s: %w", service, err)
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
