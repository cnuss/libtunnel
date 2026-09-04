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
	"errors"
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
	"github.com/rs/zerolog"

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

// edgeWatcher tracks the tunnel's edge connections from the Observer sink:
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
// what the ErrEdgeUnreachable bound reports.
//
// It calls disconnect on every Disconnected, which the supervisor defers around
// each serve attempt. That fires whether or not the attempt ever connected, so
// the count says how many serve attempts ended — not how many live connections
// were lost, and not why.
type edgeWatcher struct {
	mu          sync.Mutex
	gen         uint64
	ch          chan struct{}
	attempts    uint64
	disconnects uint64
	// connected records which connection indexes have registered before, so a
	// reconnect can be told from a first connect. HA keeps this to a handful.
	connected map[uint8]bool
}

func newEdgeWatcher() *edgeWatcher { return &edgeWatcher{ch: make(chan struct{})} }

func (e *edgeWatcher) generation() (uint64, <-chan struct{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gen, e.ch
}

// up records a Connected for index, reporting whether it is that connection's
// first.
func (e *edgeWatcher) up(index uint8) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gen++
	close(e.ch)
	e.ch = make(chan struct{})
	first := !e.connected[index]
	if e.connected == nil {
		e.connected = map[uint8]bool{}
	}
	e.connected[index] = true
	return first
}

func (e *edgeWatcher) attempt() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attempts++
}

func (e *edgeWatcher) disconnect() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disconnects++
}

func (e *edgeWatcher) disconnectCount() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.disconnects
}

func (e *edgeWatcher) attemptCount() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.attempts
}

// edgeEventName renders an Observer event for a log line. cloudflared's Status
// is an unnamed int, so an unrecognized one is reported as itself rather than
// guessed at.
func edgeEventName(s connection.Status) string {
	switch s {
	case connection.Connected:
		return "connected"
	case connection.Disconnected:
		return "disconnected"
	case connection.Reconnecting:
		return "reconnecting"
	case connection.RegisteringTunnel:
		return "registering"
	case connection.Unregistering:
		return "unregistering"
	case connection.SetURL:
		return "set-url"
	default:
		return fmt.Sprintf("status(%d)", int(s))
	}
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
	// hints is the spec being replayed (From). Its identity rides the mint
	// request so the provider can hand the same tunnel back, but unlike
	// fields it is never overlaid onto the result — a spec the provider
	// substitutes must come back as the provider wrote it, or a stale id
	// would be stamped over a fresh one. Nil unless this backend is a replay.
	hints *Spec
	// providerHost overrides the quick-tunnel mint provider host (WithProvider);
	// the endpoint https://<host>/tunnel is synthesized from it (a value carrying
	// a scheme is used verbatim). Empty means the default (tunnel.pizza);
	// v1.CloudflareProviderEnv supersedes either.
	providerHost string
	// edgeProtocol pins the edge transport (WithEdgeProtocol). Empty leaves the
	// choice to cloudflared; v1.CloudflareEdgeProtocolEnv supersedes either.
	edgeProtocol EdgeProtocol
	// headers carries request headers added to the quick-tunnel mint call via
	// WithHeader. Nil until the first WithHeader; overlaid by (and augmented
	// with) v1.CloudflareHeadersEnv at mint time. Mint-only — adopted, replayed,
	// and pinned specs never hit the API, so these never apply to them.
	headers http.Header
	// Runtime state wired at connect. reconnected feeds the supervisor's
	// external-control channel, edge tracks edge connections, edgeReject
	// carries a refused registration back from the log bridge, and reconnectCtx
	// is the tunnel context Reconnect waits on; proxy is the origin reverse proxy
	// and listener is the loopback socket cloudflared dials to reach it. All nil
	// until connect runs.
	reconnected  chan supervisor.ReconnectSignal
	edge         *edgeWatcher
	edgeReject   *edgeReject
	gone         goneWatch
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

// From returns a Cloudflare backend that replays spec: its identity rides the
// mint request as its record id, so the provider hands the same tunnel back
// when it still exists. It backs libtunnel.From.
//
// The provider always answers with a working spec, substituting when the
// original is gone. A substitution that keeps the hostname is honored
// silently — the identity a caller serves on survived, and only the tunnel
// behind it is new. One that does not is an error (see replayCheck): a caller
// replaying a specific spec is owed that news here, in one round trip, rather
// than at the edge thirty seconds later.
//
// It sits at the end of the env chain, so LIBTUNNEL_SPEC and LIBTUNNEL_FROM
// still override it (env beats code).
func From(spec *Spec) *Backend {
	b := New()
	b.hints = spec
	return b
}

// recordHint is the record a replay resumes, from the spec being replayed.
// Empty mints a fresh hostname.
func (b *Backend) recordHint() string {
	if b.hints == nil {
		return ""
	}
	return b.hints.RecordID
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
	if b.reconnected == nil || b.edge == nil || b.reconnectCtx == nil {
		return fmt.Errorf("cloudflare: Reconnect before tunnel connected")
	}
	// Wait on the caller's ctx (its deadline/cancellation) and on the tunnel
	// context, so a tunnel teardown mid-reconnect unblocks even if ctx does not.
	done := b.reconnectCtx.Done()
	base, _ := b.edge.generation()
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
		gen, ch := b.edge.generation()
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
// resolve entirely. None of them ride the mint request: what resumes a
// hostname is the record id on a replayed spec (see recordHint). Each is
// superseded
// field-by-field by its LIBTUNNEL__CLOUDFLARE_* variable (env beats code).
// They return the concrete backend, so chain them before the v1.Backend
// mutators (WithTLS, WithHTTP2), which return the interface.

// WithID sets the tunnel ID (a UUID). Env mirror: LIBTUNNEL__CLOUDFLARE_ID.
//
// It carries only as part of a complete credential set — with hostname,
// account tag and secret — which is the spec, resolved without a mint.
// Anything that resolves a spec assigns its own id, so a partial set leaves
// this unused.
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

// EdgeProtocol is a transport cloudflared can use to reach the tunnel edge.
type EdgeProtocol string

const (
	// EdgeQUIC reaches the edge over UDP. The edge closes a QUIC connection
	// when the tunnel behind it goes away, so a client learns in seconds what
	// http2 leaves it to discover minutes later.
	EdgeQUIC EdgeProtocol = "quic"
	// EdgeHTTP2 reaches the edge over TCP, which works on networks that drop
	// UDP.
	EdgeHTTP2 EdgeProtocol = "http2"
	// EdgeAuto leaves the choice, and the fallback, to cloudflared.
	EdgeAuto EdgeProtocol = "auto"
)

// WithEdgeProtocol pins the edge transport. Unset, cloudflared chooses and
// falls back on its own, which is the right default: it knows QUIC to http2,
// and it is the thing holding the connection when a transport turns out not to
// work.
//
// Pin EdgeHTTP2 on a network known to drop UDP, where the fallback would
// otherwise cost a minute before landing there anyway. Pin EdgeQUIC to refuse
// that fallback, keeping the signal http2 does not carry.
//
// Not to be confused with WithHTTP2, which is about the other end of the
// tunnel — whether the origin is dialed over HTTP/2.
//
// Env mirror: LIBTUNNEL__CLOUDFLARE_EDGE_PROTOCOL (env beats code). An
// unrecognized protocol fails the tunnel at connect rather than falling back
// silently — naming a transport means it.
func (b *Backend) WithEdgeProtocol(p EdgeProtocol) *Backend {
	b.edgeProtocol = p
	return b
}

// resolveEdgeProtocol reports the transport to hand cloudflared: the env
// mirror over the code value, and EdgeAuto when neither is set.
func (b *Backend) resolveEdgeProtocol() (EdgeProtocol, error) {
	p := b.edgeProtocol
	if raw := strings.TrimSpace(os.Getenv(v1.CloudflareEdgeProtocolEnv)); raw != "" {
		p = EdgeProtocol(raw)
	}
	switch p {
	case "":
		return EdgeAuto, nil
	case EdgeQUIC, EdgeHTTP2, EdgeAuto:
		return p, nil
	default:
		return "", fmt.Errorf("unknown edge protocol %q, want one of %q, %q, %q", p, EdgeQUIC, EdgeHTTP2, EdgeAuto)
	}
}

// WithHeader adds a request header to the quick-tunnel mint call, so a provider
// can vary what it returns based on the request (e.g. X-Opaque: true asking for
// a less-guessable hostname). Repeatable — successive calls accumulate, and
// repeating a key adds another value. Env mirror: LIBTUNNEL__CLOUDFLARE_HEADERS,
// a comma-separated K=V list, whose entries beat code per key. Applied over the
// headers the mint sets itself (Content-Type, User-Agent) and over the reclaim
// record id, so a caller may override any of
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
		qt.Headers = mintHeaders(b.headers)
		qt.record = b.recordHint()
		next = qt
	}
	if b.hints != nil {
		next = &replayCheck{spec: b.hints, next: next}
	}
	return v1alpha1.Env(b.Name(), overlay{fields: b.fields, next: v1alpha1.Replay(b.Name(), next)})
}

// replayCheck reports what a replay got and serves the spec unchanged when the
// provider cannot be reached at all.
//
// It does not reject a substitute. By the time it runs the mint has happened
// and a real tunnel exists, so refusing the spec strands that tunnel and
// leaves the caller no move but to mint a second one for the new hostname it
// was already being handed (#175).
type replayCheck struct {
	spec *Spec
	next v1.Provider[*Spec]
	log  *slog.Logger
}

// SetLogger keeps the tunnel's logger for the notices below and forwards it to
// the wrapped provider.
func (p *replayCheck) SetLogger(log *slog.Logger) {
	p.log = log
	if pl, ok := p.next.(v1alpha1.LoggerSetter); ok {
		pl.SetLogger(log)
	}
}

func (p *replayCheck) Spec(ctx context.Context) (*Spec, error) {
	got, err := p.next.Spec(ctx)
	if err != nil {
		// An endpoint that never answered is not a verdict on the spec. Serve
		// it as given so a complete credential set still starts an air-gapped
		// or flaky-network process; a spec that turns out to be dead then
		// fails at the edge, which is where it failed before any of this.
		if !errors.Is(err, v1.ErrProviderUnreachable) {
			return nil, err
		}
		p.logf("mint provider unreachable, replaying the spec as given", "error", err,
			"hostname", p.spec.GetHostname())
		return p.spec, nil
	}

	want := p.spec.GetHostname()
	switch {
	case want == "" || got == nil:
	case got.GetHostname() != want:
		// The reservation is gone. The hostname changes whether or not this
		// spec is used, so a caller holding the old one needs telling — it is
		// the only notice it gets.
		p.logf("replayed hostname is gone, adopting the one minted for it",
			"was", want, "now", got.GetHostname())
	case got.ID != p.spec.ID:
		p.logf("tunnel replaced behind the same hostname", "hostname", want,
			"was", p.spec.ID, "now", got.ID)
	}
	return got, nil
}

func (p *replayCheck) logf(msg string, args ...any) {
	if p.log != nil {
		p.log.Warn(msg, args...)
	}
}

// mintHeaders resolves the caller's mint request headers: the code headers
// (WithHeader), then v1.CloudflareHeadersEnv, a comma-separated K=V list (env
// beats code). Returns nil when both are empty. Values cannot contain a comma
// or an equals sign — the env form has no escaping.
//
// Spec fields are not among them. What resumes a hostname is the record the
// provider handed back (see recordHint), which QuickTunnelProvider sends
// itself.
func mintHeaders(code http.Header) http.Header {
	var out http.Header

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
	// Not the id: whatever resolved the spec — mint, replay, adopt — owns it,
	// and overwriting it here leaves a spec whose id is not its tunnel's. A
	// caller supplying one supplies all four, which returns above.
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

// caCertPool is the trust set for the connections libtunnel makes on its own
// behalf. The host's store when it has one, plus the roots compiled into the
// binary — so a scratch, busybox or distroless-without-certs image mints and
// connects without anyone installing ca-certificates first.
//
// A host with no store is not an error: SystemCertPool yields an empty pool
// there, and the embedded roots go on top either way, which is the point.
var caCertPool = sync.OnceValue(func() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	for _, c := range caCerts() {
		pool.AddCert(c)
	}
	return pool
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
	// external-control channel (see NewSupervisor below), edge counts Connected
	// events via the Observer sink, reconnectCtx is the tunnel context, and
	// proxy/listener back the Engine's Proxy/Listener (seeding each interception's
	// default handler and Target). Once set, b.Reconnect and the interceptor
	// pipeline are live.
	b.reconnected = make(chan supervisor.ReconnectSignal)
	b.edge = newEdgeWatcher()
	b.edgeReject = newEdgeReject()
	b.reconnectCtx = t.Context()
	wsOrigin, _ := t.WebSocketOrigin()
	b.proxy = newOriginProxy(originURLs, wsOrigin, t.Logger(), transport)
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
	log := zerologger(t.Logger(), b.edgeReject)
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

	protocol, err := b.resolveEdgeProtocol()
	if err != nil {
		return err
	}
	t.Logger().Info("edge transport selected", "protocol", protocol)

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
		protocolSelector, err := connection.NewProtocolSelector(string(protocol), spec.AccountTag, false, edgediscovery.ProtocolPercentage, connection.ResolveTTL, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create protocol selector: %w", err)
		}

		originDialer := ingress.NewOriginDialer(ingress.OriginConfig{}, log)

		// The observer fans connection lifecycle events out to sinks; wire one
		// that feeds edge, so the Reconnect lever can block until the edge is
		// back up and the ErrEdgeUnreachable bound can report how many attempts
		// it took.
		observer := connection.NewObserver(log, log)
		observer.RegisterSink(connection.EventSinkFunc(func(e connection.Event) {
			// Every event, not only the two acted on: this is the only
			// structured view of what the edge is doing, and cloudflared's own
			// account of it is prose in a log line.
			// Only Connected carries a protocol, location and address; the
			// rest leave them zero, and connection.HTTP2 is 0 — logging it
			// unconditionally reports http2 for every event on a QUIC tunnel.
			attrs := []any{"event", edgeEventName(e.EventType), "connIndex", e.Index}
			if e.EventType == connection.Connected {
				attrs = append(attrs, "protocol", e.Protocol.String(),
					"location", e.Location, "edgeAddress", e.EdgeAddress)
			}
			if e.URL != "" {
				attrs = append(attrs, "url", e.URL)
			}
			t.Logger().Debug("edge event", attrs...)
			switch e.EventType {
			case connection.Connected:
				// First time for this connection index is a connect; after
				// that the edge has dropped it and taken it back.
				kind := v1.EventReconnected
				if b.edge.up(e.Index) {
					kind = v1.EventConnected
				}
				b.gone.up()
				t.Emit(v1.Event{Kind: kind})
			case connection.Reconnecting:
				b.edge.attempt()
			case connection.Disconnected:
				b.edge.disconnect()
				t.Emit(v1.Event{Kind: v1.EventDisconnected})
				// The only trigger: nothing probes the edge unless it has
				// already dropped us and stayed away for goneSettle.
				b.gone.down(func() { b.probeGone(ctx, t, spec, log) })
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
			// Empty: cloudflared discovers the edge by SRV, with its own DoT
			// fallback when the machine's resolver cannot answer.
			EdgeAddrs:     nil,
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
				pool := caCertPool()
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

	// The bound on the first edge connection, read off the class that reports
	// it — see v1.ErrEdgeUnreachable for why thirty seconds and why only the
	// first connection.
	edgeBudget := v1.Budget(v1.ErrEdgeUnreachable)
	timeout := time.NewTimer(edgeBudget)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connected.Wait():
	case <-b.edgeReject.wait():
		return b.credentialRejected()
	case <-timeout.C:
		return fmt.Errorf("%w: no connection after %d attempts (%d ended) in %s: %s",
			v1.ErrEdgeUnreachable, b.edge.attemptCount(), b.edge.disconnectCount(), edgeBudget, edgeBlockedHint)
	}
	return nil
}

// probeGone asks the edge whether the tunnel still exists and reports it if
// not. Reporting only: cloudflared keeps retrying either way, and ending the
// tunnel on the strength of one probe is the caller's call to make.
func (b *Backend) probeGone(ctx context.Context, t emitter, spec *Spec, log *zerolog.Logger) {
	gone, known := tunnelGone(ctx, spec, log)
	switch {
	case !known:
		// The edge never answered, so nothing was learned. Leave the watch
		// fired: a second probe would ask the same unanswerable question.
		return
	case !gone:
		return
	}
	t.Emit(v1.Event{Kind: v1.EventGone})
}

// credentialRejected is what a caller sees when the edge refuses these
// credentials: the class it can branch on, carrying the edge's own words and
// none of edgeBlockedHint's advice, which is about a network this failure has
// nothing to do with.
func (b *Backend) credentialRejected() error {
	return fmt.Errorf("%w: %s", v1.ErrCredentialRejected, b.edgeReject.message())
}

// edgeBlockedHint is cloudflared's own diagnosis of this failure, which it logs
// at warn level from selectNextProtocol. Repeated verbatim so the error carries
// the same guidance without the caller having to correlate it with a log line.
//
// It rides only the timeout branch. A credential the edge refuses leaves
// through its own case above, so reaching this means nothing better is known
// about why the edge never answered.
const edgeBlockedHint = "your machine/network is getting its egress to the tunnel edge " +
	"blocked or dropped. Make sure to allow egress connectivity as per " +
	"https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/configuration/ports-and-ips/ " +
	"(WithEdgeProtocol pins the transport when only one of UDP or TCP is allowed)"

// newOriginProxy builds the reverse proxy that always fronts the origins (see
// connect, which serves it on a plaintext listener cloudflared dials). When an
// origin scheme is https the Transport dials it over TLS with InsecureSkipVerify,
// matching the engine's always-off origin verification. Every response is
// relayed verbatim — status, headers, body untouched.
//
// With more than one origin the proxy routes per request, resolving the index
// as: a bare numeric query parameter (?n, empty value, dropped from the
// forwarded query), else — for a WebSocket handshake — the origin declared to
// own WebSockets (wsOrigin, the +ws scheme marker, -1 for none), else a
// same-host Referer carrying one (an iframe's or page's subresources follow
// their document URL — per-tab, no shared state), else the sticky
// originCookie, else originURLs[0]. The declaration sits above the cookie
// deliberately: the cookie is a per-browser guess, the declaration an
// operator-stated fact, and a fact beats a guess. It sits below an explicit
// parameter so a page carrying its own index — and every tile of a multiview
// panel — is unaffected. An explicit parameter on
// a top-level navigation answers with the sticky cookie so parameter-less
// follow-ups (an address-bar visit, a bookmark) stay on the same origin — an
// iframe's pick does not, or side-by-side iframes would fight over the shared
// jar. Anything out of range falls back to originURLs[0]. A single origin
// skips all of it — the pre-routing proxy.
func newOriginProxy(originURLs []*url.URL, wsOrigin int, log *slog.Logger, transport http.RoundTripper) *httputil.ReverseProxy {
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
				upgrade := r.In.Header.Get("Upgrade") != ""
				if !explicit {
					switch n, ok := refererIndex(r.In); {
					case upgrade && wsOrigin >= 0:
						// A handshake carries no Referer and no per-tab signal
						// of any kind, so the declaration is the only thing
						// that can route it.
						ix = wsOrigin
					case ok:
						ix = n
					default:
						cookie, err := r.In.Cookie(originCookie)
						if err == nil {
							if n, err := strconv.Atoi(cookie.Value); err == nil {
								ix = n
							}
						}
						if upgrade && err != nil {
							// Nothing to route on: no parameter, no
							// declaration, no cookie. It still goes to origin
							// 0 — a client explicit enough to be broken by a
							// refusal is working by luck today — but silence
							// here is the worst available failure: the page
							// loads, the socket connects to the wrong origin,
							// the app half-works, and the tunnel is the last
							// thing anybody suspects (#159).
							log.Warn("websocket could not be routed and fell back to the default origin; mark the origin that owns websockets with the +ws scheme suffix (http+ws://host)",
								"url", r.In.URL.String(), "origin", originURLs[0].Redacted())
						}
					}
				}
				if ix < 0 || ix >= len(originURLs) {
					ix = 0
				}
				origin = originURLs[ix]
				r.Out.URL.RawQuery = strings.Join(kept, "&")
				if explicit && navigation(r.In) {
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

// navigation reports whether a request is a top-level navigation — the only
// kind whose explicit ?n pick may write the tab-wide sticky cookie.
// Sec-Fetch-Dest names it outright in a modern browser; an absent header is
// treated as one so a client that predates the header (curl, an old browser)
// can still pin an origin. A WebSocket handshake is the exception that
// forces the check: it carries no Sec-Fetch-Dest at all, so the absent case
// used to catch every socket, letting whichever socket connected last re-pin
// every later parameter-less request (#159). An upgrade is never a
// navigation, whatever else it omits.
func navigation(r *http.Request) bool {
	if r.Header.Get("Upgrade") != "" {
		return false
	}
	dest := r.Header.Get("Sec-Fetch-Dest")
	return dest == "" || dest == "document"
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
