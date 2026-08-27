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
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
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

// haConnections is the number of edge (HA) connections the supervisor keeps.
// The reconnect lever fires one ReconnectSignal per conn to cycle them all.
const haConnections = 2

// edgeUpWatcher tracks the tunnel's edge connections from the Observer sink:
// Connected events, so a caller can wait for N of them past a barrier, and the
// failed attempts between them.
//
// The sink calls up on every Connected; generation returns the running count
// plus a channel that closes on the next one. Because each delivered
// ReconnectSignal breaks exactly one edge conn and thus yields exactly one
// Connected, waiting for the count to advance by haConnections is a correct
// "all cycled conns are back up" barrier for any HA count.
//
// The sink calls attempt on every Reconnecting, which the supervisor sends
// before each backoff — including after a dial that never connected, so before
// the first Connected the count is failed attempts to reach the edge, which is
// what edgeTimeout reports.
type edgeUpWatcher struct {
	mu       sync.Mutex
	gen      uint64
	ch       chan struct{}
	attempts uint64
}

func newEdgeUpWatcher() *edgeUpWatcher { return &edgeUpWatcher{ch: make(chan struct{})} }

func (e *edgeUpWatcher) generation() (uint64, <-chan struct{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gen, e.ch
}

func (e *edgeUpWatcher) up() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gen++
	close(e.ch)
	e.ch = make(chan struct{})
}

func (e *edgeUpWatcher) attempt() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attempts++
}

func (e *edgeUpWatcher) attemptCount() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.attempts
}

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
	// providerHost overrides the quick-tunnel mint provider host (WithProvider);
	// the endpoint https://<host>/tunnel is synthesized from it (a value carrying
	// a scheme is used verbatim). Empty means the default (tunnel.pizza);
	// v1.CloudflareProviderEnv supersedes either.
	providerHost string
	// edgeAddrs pins the cloudflared<->edge addresses (WithEdge), bypassing the
	// SRV discovery that otherwise yields Cloudflare's edge on port 7844. Empty
	// means discover; v1.CloudflareEdgeEnv supersedes either.
	edgeAddrs []string
	// headers carries request headers added to the quick-tunnel mint call via
	// WithHeader. Nil until the first WithHeader; overlaid by (and augmented
	// with) v1.CloudflareHeadersEnv at mint time. Mint-only — adopted, replayed,
	// and pinned specs never hit the API, so these never apply to them.
	headers http.Header
	// Runtime state wired at connect. reconnected feeds the supervisor's
	// external-control channel, edgeUp tracks edge connections, and reconnectCtx
	// is the tunnel context Reconnect waits on; proxy is the origin reverse proxy
	// and listener is the loopback socket cloudflared dials to reach it. All nil
	// until connect runs.
	reconnected  chan supervisor.ReconnectSignal
	edgeUp       *edgeUpWatcher
	reconnectCtx context.Context
	proxy        *httputil.ReverseProxy
	listener     net.Listener
}

// Proxy returns the origin reverse proxy (nil before connect). Implements the
// v1alpha1 Engine contract.
func (b *Backend) Proxy() *httputil.ReverseProxy { return b.proxy }

// Listener returns the loopback listener cloudflared dials to reach the proxy
// (nil before connect). Implements the v1alpha1 Engine contract.
func (b *Backend) Listener() net.Listener { return b.listener }

// New returns the Cloudflare backend. The origin-scheme knobs are fixed from
// the environment here when LIBTUNNEL_TLS / LIBTUNNEL_HTTP2 are set. The first
// unparsable value wins and is surfaced at connect.
func New() *Backend {
	b := &Backend{}
	b.tls, b.tlsFixed, b.envErr = v1alpha1.EnvBool(v1.TLSEnv)
	if b.envErr == nil {
		b.http2, b.http2Fixed, b.envErr = v1alpha1.EnvBool(v1.HTTP2Env)
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

// Reconnect forcefully cycles the cloudflared<->edge tunnel(s) and blocks until
// they are re-established, ctx is done, or the tunnel shuts down (see
// v1.Backend.Reconnect). It fires one ReconnectSignal per HA connection, then
// waits for haConnections Connected events past the pre-send count — each
// delivered signal breaks exactly one edge conn and thus yields exactly one
// Connected, so the barrier is correct for any HA count. Errors if called before
// the tunnel has connected.
func (b *Backend) Reconnect(ctx context.Context) error {
	if b.reconnected == nil || b.edgeUp == nil || b.reconnectCtx == nil {
		return fmt.Errorf("cloudflare: Reconnect before tunnel connected")
	}
	// Wait on the caller's ctx (its deadline/cancellation) and on the tunnel
	// context, so a tunnel teardown mid-reconnect unblocks even if ctx does not.
	done := b.reconnectCtx.Done()
	base, _ := b.edgeUp.generation()
	for range haConnections {
		select {
		case b.reconnected <- supervisor.ReconnectSignal{}:
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return b.reconnectCtx.Err()
		}
	}
	for {
		gen, ch := b.edgeUp.generation()
		if gen-base >= haConnections {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return b.reconnectCtx.Err()
		}
	}
}

// The spec-field setters override individual fields of whatever spec the
// credential chain resolves — adopt, replay, pin, or mint — and a complete
// credential set (id, hostname, account tag, secret) short-circuits the
// resolve entirely. When the chain does mint, the fields known beforehand
// also ride the mint request as reclaim hints — X-Id, X-Name, X-Secret
// (base64) — so a provider that reaps idle tunnels can hand the matching
// tunnel back instead of minting fresh (see mintHeaders; hint keys the
// caller leaves unset are seeded from the most recently minted spec,
// latest.spec.json — see QuickTunnelProvider.Spec). Each is superseded
// field-by-field by its LIBTUNNEL__CLOUDFLARE_* variable (env beats code).
// They return the concrete backend, so chain them before the v1.Backend
// mutators (WithTLS, WithHTTP2), which return the interface.

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

// WithProvider overrides the quick-tunnel mint provider host (default
// tunnel.pizza); the endpoint https://<host>/tunnel is synthesized
// from it — pass just the host, the scheme and path are assumed. A value that
// carries a scheme (e.g. http://127.0.0.1:8080/tunnel) is used verbatim, for
// pointing the mint at a mock or alternate endpoint. Env mirror:
// LIBTUNNEL__CLOUDFLARE_PROVIDER (env beats code). Only the mint path uses it —
// adopted, replayed, and pinned specs never hit the API.
func (b *Backend) WithProvider(host string) *Backend {
	b.providerHost = host
	return b
}

// WithEdge pins the addresses cloudflared dials to reach the tunnel edge,
// bypassing SRV discovery (_v2-origintunneld._tcp.argotunnel.com), which
// otherwise resolves to Cloudflare's edge on port 7844. Each address is
// host:port, dialed over TCP (see edgeProtocol).
//
// The intended use is a relay: a network that blocks outbound 7844 can still
// reach the edge through a TCP relay on an allowed port (443), which splices
// bytes to a real edge address. The connector's TLS to the edge is end-to-end
// with a fixed server name (h2.cftunnel.com), so a relay that does not
// terminate TLS keeps certificate verification intact — it cannot read the
// traffic, and neither the tunnel nor its credentials change.
//
// A TCP relay can serve this because the edge transport is TCP for every tunnel,
// pinned or not (see edgeProtocol) — nothing here has to opt out of QUIC.
// Whatever is dialed must ultimately reach a real edge; nothing else speaks the
// tunnel protocol. Env mirror: LIBTUNNEL__CLOUDFLARE_EDGE (comma-separated; env
// beats code).
func (b *Backend) WithEdge(addrs ...string) *Backend {
	b.edgeAddrs = addrs
	return b
}

// edgeProtocol is the edge transport, fixed to TCP rather than left to
// cloudflared's "auto" (QUIC, falling back to http2).
//
// QUIC needs egress UDP to 7844, which a great many networks drop — hotel and
// guest wifi, corporate egress filters, CI runners — while carrying TCP to the
// same port perfectly well. cloudflared does recover from that, but only after
// exhausting six QUIC retries on a backoff capped at 1m4s, so the recovery costs
// minutes during which the tunnel is simply not up. Choosing the transport that
// works everywhere costs nothing this library uses: QUIC's advantages here are
// datagram support for private-network routing (ICMP, UDP), which a quick tunnel
// serving HTTP does not do.
//
// It also makes a pinned edge (WithEdge) work without a special case — a relay
// on an allowed port is a TCP splice, and "auto" would have dialled QUIC over
// UDP to it and stalled there first.
const edgeProtocol = "http2"

// defaultEdgeAddrs is where the edge is dialed when nothing pins it, replacing
// cloudflared's SRV discovery of _v2-origintunneld._tcp.argotunnel.com.
//
// The SRV lookup is one more thing that has to work before a tunnel can start,
// on the machine's own resolver, on a library whose entire premise is that that
// resolver cannot be relied upon. These are that lookup's answer verbatim, in
// its priority order, so naming them directly removes the step without changing
// where the connection goes:
//
//	$ dig +short SRV _v2-origintunneld._tcp.argotunnel.com
//	1 1 7844 region1.v2.argotunnel.com.
//	2 1 7844 region2.v2.argotunnel.com.
//
// Names rather than addresses: the pool behind each region is renumbered at
// Cloudflare's discretion, and a hardcoded address list is wrong the day that
// happens. The cost is that cloudflared's ResolveAddrs keeps at most one address
// per name (edgediscovery/allregions/discovery.go), so this yields two edge
// addresses where SRV yielded twenty — enough for its rotation to have somewhere
// to go, but thinner. A caller who needs the full spread, or who needs no DNS at
// all, pins addresses with WithEdge.
var defaultEdgeAddrs = []string{
	"region1.v2.argotunnel.com:7844",
	"region2.v2.argotunnel.com:7844",
}

// edgeAddresses resolves the edge addresses: the code value (WithEdge)
// superseded wholesale by v1.CloudflareEdgeEnv, a comma-separated list, and
// defaultEdgeAddrs when neither is set.
func edgeAddresses(code []string) []string {
	raw := os.Getenv(v1.CloudflareEdgeEnv)
	if raw == "" {
		if len(code) == 0 {
			return defaultEdgeAddrs
		}
		return code
	}
	var out []string
	for _, addr := range strings.Split(raw, ",") {
		if addr = strings.TrimSpace(addr); addr != "" {
			out = append(out, addr)
		}
	}
	return out
}

// WithHeader adds a request header to the quick-tunnel mint call, so a provider
// can vary what it returns based on the request (e.g. X-Opaque: true asking for
// a less-guessable hostname). Repeatable — successive calls accumulate, and
// repeating a key adds another value. Env mirror: LIBTUNNEL__CLOUDFLARE_HEADERS,
// a comma-separated K=V list, whose entries beat code per key. Applied over the
// headers the mint sets itself (Content-Type, User-Agent) and over the reclaim
// hints (X-Id, X-Name, X-Secret — see WithID), so a caller may override any of
// them — overriding User-Agent changes how the endpoint sees the
// connector version. Mint-only, following the WithProvider boundary: adopted,
// replayed, and pinned specs never hit the API, so headers never apply to them.
func (b *Backend) WithHeader(key, value string) *Backend {
	if b.headers == nil {
		b.headers = http.Header{}
	}
	b.headers.Add(key, value)
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
// quick tunnel from tunnel.pizza.
func (b *Backend) Provider() v1.Provider[*Spec] {
	next := b.provider
	if next == nil {
		host := b.providerHost
		stringEnv(v1.CloudflareProviderEnv, &host) // env beats code
		qt := QuickTunnel()
		if host != "" {
			qt.URL = providerEndpoint(host)
		}
		qt.Headers = mintHeaders(b.fields, b.headers)
		next = qt
	}
	return v1alpha1.Env(b.Name(), overlay{fields: b.fields, next: v1alpha1.Replay(b.Name(), next)})
}

// mintHeaders resolves the mint request headers, three layers, each beating
// the one before it per key. First the reclaim hints: the spec fields known
// before minting (WithID / WithName / WithSecret, each superseded by its
// LIBTUNNEL__CLOUDFLARE_* mirror), sent as X-Id, X-Name, and X-Secret
// (base64) so a provider that reaps idle tunnels can hand the matching tunnel
// back instead of minting fresh — optimistic, so whatever is known is sent
// and absent fields send nothing. Then the code headers (WithHeader), then
// v1.CloudflareHeadersEnv, a comma-separated K=V list (env beats code).
// Returns nil when all three are empty. Values cannot contain a comma or an
// equals sign — the env form has no escaping.
func mintHeaders(fields Spec, code http.Header) http.Header {
	var out http.Header
	set := func(key, value string) {
		if out == nil {
			out = http.Header{}
		}
		out.Set(key, value)
	}

	stringEnv(v1.CloudflareIDEnv, &fields.ID)
	stringEnv(v1.CloudflareNameEnv, &fields.Name)
	if v := os.Getenv(v1.CloudflareSecretEnv); v != "" {
		// An undecodable value is ignored rather than surfaced: the overlay
		// decodes the same variable before any mint runs and fails resolution.
		if secret, err := base64.StdEncoding.DecodeString(v); err == nil {
			fields.Secret = secret
		}
	}
	if fields.ID != "" {
		set("X-Id", fields.ID)
	}
	if fields.Name != "" {
		set("X-Name", fields.Name)
	}
	if len(fields.Secret) > 0 {
		set("X-Secret", base64.StdEncoding.EncodeToString(fields.Secret))
	}

	for key, values := range code {
		if out == nil {
			out = http.Header{}
		}
		out.Del(key)
		for _, v := range values {
			out.Add(key, v)
		}
	}

	raw := os.Getenv(v1.CloudflareHeadersEnv)
	if raw == "" {
		return out
	}
	if out == nil {
		out = http.Header{}
	}
	for _, pair := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if k = strings.TrimSpace(k); !ok || k == "" {
			continue
		}
		out.Set(k, strings.TrimSpace(v))
	}
	return out
}

// providerEndpoint turns a quick-tunnel provider host into a mint endpoint URL:
// https://<host>/tunnel. A value that already carries a scheme is returned
// verbatim, so a full URL (a mock or alternate endpoint) still works.
func providerEndpoint(host string) string {
	if strings.Contains(host, "://") {
		return host
	}
	return "https://" + host + "/tunnel"
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
	return b.connect(t, []*url.URL{{Scheme: scheme, Host: l.Addr().String()}})
}

// WithLocalURL dials the Cloudflare edge and proxies it onto already-running
// local origins. The URLs arrive validated and reduced to scheme+host by the
// core, so each scheme — not WithTLS — declares how that origin is dialed.
func (b *Backend) WithLocalURL(t *v1alpha1.TunnelImpl[*Spec], urls []*url.URL) error {
	return b.connect(t, urls)
}

// connect is the shared engine body behind WithListener and WithLocalURL:
// originURLs are the local services the edge proxies to — originURLs[0] the
// default, the rest reachable via ?n routing (see newOriginProxy).
func (b *Backend) connect(t *v1alpha1.TunnelImpl[*Spec], originURLs []*url.URL) error {
	if b.envErr != nil {
		return b.envErr
	}
	// An in-process reverse proxy always fronts the origin. It re-dials the
	// origin (adding TLS when the origin scheme is https) and relays the
	// response verbatim. cloudflared -> proxy is always plaintext (the proxy
	// listens on a plain TCP socket), so the ingress service is rewritten to
	// http regardless of the origin's scheme — a leftover https would make
	// cloudflared TLS-dial the plaintext proxy → 502.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("reverse proxy: %w", err)
	}
	transport := originTransport(originURLs)
	// Wire runtime state onto the backend: reconnected feeds the supervisor's
	// external-control channel (see NewSupervisor below), edgeUp counts Connected
	// events via the Observer sink, reconnectCtx is the tunnel context, and
	// proxy/listener back the Engine's Proxy/Listener (seeding each interception's
	// default handler and Target). Once set, b.Reconnect and the interceptor
	// pipeline are live.
	b.reconnected = make(chan supervisor.ReconnectSignal)
	b.edgeUp = newEdgeUpWatcher()
	b.reconnectCtx = t.Context()
	b.proxy = newOriginProxy(originURLs, t.Logger(), transport)
	b.listener = l
	handler := originRedirect(len(originURLs), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Intercept(v1alpha1.NewInterceptCtx(b, w, r))(w, r)
	}))
	srv := &http.Server{Handler: handler}
	context.AfterFunc(t.Context(), func() { srv.Close() })
	go srv.Serve(l)
	t.Logger().Info("reverse proxy interposed", "listen", l.Addr().String(), "origins", originURLs)
	service := (&url.URL{Scheme: "http", Host: l.Addr().String()}).String()
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

	edgeAddrs := edgeAddresses(b.edgeAddrs)
	t.Logger().Info("edge addresses set, skipping SRV discovery", "addrs", edgeAddrs, "protocol", edgeProtocol)

	// The closure scopes the prometheus.DefaultRegisterer swap to supervisor
	// construction: cloudflared registers collectors against the global
	// registerer at construction, which would collide across tunnels and
	// pollute the host application's metrics, so it is pointed at a noop
	// (under promMu) and restored by defer when construction finishes. The
	// supervisor's run and the wait for the first edge connection happen below,
	// outside the lock, so concurrent tunnels neither serialize behind one
	// tunnel's connect nor discard the host's own registrations in the meantime.
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
		protocolSelector, err := connection.NewProtocolSelector(edgeProtocol, spec.AccountTag, false, edgediscovery.ProtocolPercentage, connection.ResolveTTL, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create protocol selector: %w", err)
		}

		originDialer := ingress.NewOriginDialer(ingress.OriginConfig{}, log)

		// The observer fans connection lifecycle events out to sinks; wire one
		// that feeds edgeUp, so the Reconnect lever can block until the edge is
		// back up and edgeTimeout can report how many attempts it took.
		observer := connection.NewObserver(log, log)
		observer.RegisterSink(connection.EventSinkFunc(func(e connection.Event) {
			switch e.EventType {
			case connection.Connected:
				b.edgeUp.up()
			case connection.Reconnecting:
				b.edgeUp.attempt()
			}
		}))

		tunnelConfig := &supervisor.TunnelConfig{
			ClientConfig: clientConfig,
			// cloudflared's own default (its --grace-period flag): how long the
			// supervisor waits for in-flight requests on graceful shutdown — and
			// ctx.Done is wired as the graceful-shutdown signal below, so this
			// bounds teardown after a cancel. Max accepted is 3m.
			GracePeriod: 30 * time.Second,
			Region:      "",
			// Non-empty pins the edge and bypasses SRV discovery (WithEdge).
			EdgeAddrs:     edgeAddrs,
			EdgeIPVersion: allregions.Auto,
			HAConnections: haConnections,
			// No tags, matching cloudflared's quick-tunnel default. (Tags never
			// were the connector ID — client.NewConfig mints a fresh random UUID
			// for that; tags only become Cf-Warp-Tag-* headers injected into
			// every request hitting the origin.)
			Tags:            nil,
			Log:             log,
			LogTransport:    log,
			Observer:        observer,
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

		// b.reconnected is the backend's external-control channel, wired above;
		// here it is handed to the supervisor, which selects on it. b.Reconnect
		// sends on it to cycle the edge.
		sup, err := supervisor.NewSupervisor(tunnelConfig, orchestrator, b.reconnected, ctx.Done())
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

	timeout := time.NewTimer(edgeTimeout)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connected.Wait():
	case <-timeout.C:
		return fmt.Errorf("%w: no connection after %d attempts in %s: %s",
			v1.ErrEdgeUnreachable, b.edgeUp.attemptCount(), edgeTimeout, edgeBlockedHint)
	}
	return nil
}

// edgeTimeout bounds the wait for the first edge connection. The supervisor
// retries forever — cloudflared builds its backoff with retryForever set, so
// TunnelConfig.Retries only caps the backoff ceiling, not the attempt count —
// which leaves a blocked network looking exactly like a slow one until the
// caller's context expires. This is the terminal state cloudflared has none of.
//
// It applies to the first connection only: connect returns once the edge is up,
// and a connection dropped later is cloudflared's to retry indefinitely, which
// is the right policy for a tunnel that has already proven the network works.
//
// Thirty seconds is a bound on one transport, not a race against a fallback to
// another: edgeProtocol fixes the edge to TCP, so there is no quic->http2
// recovery in flight that a short bound could cut off. An earlier version of
// this had to outlast that fallback and did not, failing a CI runner after four
// QUIC attempts while http2 was still ahead of it. With the transport fixed, a
// TCP connect and registration that has not happened in thirty seconds is not
// going to.
const edgeTimeout = 30 * time.Second

// edgeBlockedHint is cloudflared's own diagnosis of this failure, which it logs
// at warn level from selectNextProtocol — where the tunnel's logger is silent
// by default (see zerologger) and it is never seen. Repeated verbatim so the
// error carries the same guidance, plus libtunnel's way around it.
const edgeBlockedHint = "your machine/network is getting its egress UDP to port 7844 (or others) " +
	"blocked or dropped. Make sure to allow egress connectivity as per " +
	"https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/configuration/ports-and-ips/ " +
	"(WithEdge relays the edge through a port that is allowed)"

// newOriginProxy builds the reverse proxy that always fronts the origins (see
// connect, which serves it on a plaintext listener cloudflared dials). When an
// origin scheme is https the Transport dials it over TLS with InsecureSkipVerify,
// matching the engine's always-off origin verification. Every response is
// relayed verbatim — status, headers, body untouched.
//
// With more than one origin the proxy routes per request, resolving the index
// as: a bare numeric query parameter (?n, empty value, dropped from the
// forwarded query), else a same-host Referer carrying one (an iframe's or
// page's subresources follow their document URL — per-tab, no shared state),
// else the sticky originCookie, else originURLs[0]. An explicit parameter on
// a top-level navigation answers with the sticky cookie so parameter-less
// follow-ups (an address-bar visit, a bookmark) stay on the same origin — an
// iframe's pick does not, or side-by-side iframes would fight over the shared
// jar. Anything out of range falls back to originURLs[0]. A single origin
// skips all of it — the pre-routing proxy.
func newOriginProxy(originURLs []*url.URL, log *slog.Logger, transport http.RoundTripper) *httputil.ReverseProxy {
	p := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			origin := originURLs[0]
			if len(originURLs) > 1 {
				// A segment Atoi accepts is exactly a bare numeric parameter:
				// valued ones ("1=foo") carry '=' and fail the parse. The first
				// wins; every routing segment is dropped from the forward.
				ix, explicit := 0, false
				kept := make([]string, 0, 4)
				for seg := range strings.SplitSeq(r.In.URL.RawQuery, "&") {
					if n, err := strconv.Atoi(seg); err == nil {
						if !explicit {
							ix, explicit = n, true
						}
						continue
					}
					if seg != "" {
						kept = append(kept, seg)
					}
				}
				if !explicit {
					if n, ok := refererIndex(r.In); ok {
						ix = n
					} else if c, err := r.In.Cookie(originCookie); err == nil {
						if n, err := strconv.Atoi(c.Value); err == nil {
							ix = n
						}
					}
				}
				if ix < 0 || ix >= len(originURLs) {
					ix = 0
				}
				origin = originURLs[ix]
				r.Out.URL.RawQuery = strings.Join(kept, "&")
				if dest := r.In.Header.Get("Sec-Fetch-Dest"); explicit && (dest == "" || dest == "document") {
					// ModifyResponse below answers an explicit top-level pick
					// with the sticky cookie; the outbound context carries the
					// index over.
					r.Out = r.Out.WithContext(context.WithValue(r.Out.Context(), stickyCookieKey{}, ix))
				}
				log.Debug("routing to origin", "ix", ix, "url", r.In.URL.String())
			}
			r.SetURL(origin)
			// Preserve the inbound Host: the origin (e.g. an apiserver) may key
			// on it, and the stdlib default would rewrite it to the origin host.
			r.Out.Host = r.In.Host
		},
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	if len(originURLs) > 1 {
		p.ModifyResponse = func(resp *http.Response) error {
			if ix, ok := resp.Request.Context().Value(stickyCookieKey{}).(int); ok {
				cookie := &http.Cookie{Name: originCookie, Value: strconv.Itoa(ix), Path: "/"}
				resp.Header.Add("Set-Cookie", cookie.String())
			}
			return nil
		}
	}
	return p
}

// originRedirect canonicalizes referer-routed navigations onto an explicit ?n
// URL, defending referer routing against decay: a GET/HEAD document or iframe
// navigation with no routing parameter of its own but a same-host referer
// that carries one (a link click inside a routed page) is answered 307 to the
// same URL plus that parameter. The new document's URL then re-pins the
// origin, so its own subresources — whose Referer is the new URL — keep
// routing instead of falling back to the default. Redirected navigations
// bypass the interceptor pipeline; everything else passes through. A single
// origin passes everything through.
func originRedirect(n int, next http.Handler) http.Handler {
	if n < 2 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := r.Header.Get("Sec-Fetch-Dest")
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
			(dest == "document" || dest == "iframe" || dest == "frame") {
			if _, explicit := bareIndex(r.URL.RawQuery); !explicit {
				// A path opening "//" (or "/\", which browsers normalize to
				// it) would echo into Location as a scheme-relative absolute
				// URL — an open redirect off the tunnel host. Those
				// navigations proxy un-canonicalized.
				if ix, ok := refererIndex(r); ok &&
					!strings.HasPrefix(r.URL.Path, "//") && !strings.HasPrefix(r.URL.Path, "/\\") {
					u := *r.URL
					if u.RawQuery != "" {
						u.RawQuery += "&"
					}
					u.RawQuery += strconv.Itoa(ix)
					http.Redirect(w, r, u.RequestURI(), http.StatusTemporaryRedirect)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// refererIndex resolves the routing index from a same-host Referer header:
// the document URL of the page (or iframe) the request originates from, whose
// query carries the bare ?n parameter. A cross-host referer never routes.
func refererIndex(r *http.Request) (int, bool) {
	ref, err := url.Parse(r.Header.Get("Referer"))
	if err != nil || ref.Host != r.Host {
		return 0, false
	}
	return bareIndex(ref.RawQuery)
}

// bareIndex scans a raw query for the first bare numeric segment — the ?n
// routing directive. Valued parameters ("1=foo") carry '=' and fail the
// parse: application data, never routing.
func bareIndex(rawQuery string) (int, bool) {
	for seg := range strings.SplitSeq(rawQuery, "&") {
		if n, err := strconv.Atoi(seg); err == nil {
			return n, true
		}
	}
	return 0, false
}

// originCookie is the sticky-routing cookie a multi-origin proxy sets when a
// request carries an explicit ?n routing parameter (see newOriginProxy).
const originCookie = "libtunnel-origin"

// stickyCookieKey carries an explicit routing pick from Rewrite to
// ModifyResponse on the outbound request context.
type stickyCookieKey struct{}

// originTransport dials the origins, adding TLS (InsecureSkipVerify, matching
// the engine's always-off origin verification) when any origin scheme is https
// (the TLS config only engages on https dials, so http origins share it).
func originTransport(originURLs []*url.URL) http.RoundTripper {
	for _, u := range originURLs {
		if u.Scheme == "https" {
			return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		}
	}
	return http.DefaultTransport
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
