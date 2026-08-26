// Package v1 is the stable public surface for libtunnel. The interfaces here
// are the contract callers depend on across releases; the implementation lives
// in v1alpha1 and may change between alpha revisions.
//
// A tunnel exposes a local origin to the public internet through a backend
// transport (Cloudflare quick tunnels first). The API is pure-lazy: every
// getter resolves on first use, and the edge connection starts on first
// demand — WithListener provides the origin listener explicitly, WithLocalURL
// points at an already-running local origin instead, and Listener, URL, and
// TunnelReady mint a loopback listener if no origin was provided.
package v1

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
)

// ErrClosed is the Err result of a tunnel shut down deliberately — by
// closing the listener returned from Tunnel.Listener.
var ErrClosed = errors.New("tunnel closed")

// ErrEdgeUnreachable is the Err result of a tunnel that never reached its
// backend's edge. The engine retries the edge indefinitely, so without a bound
// a blocked network is indistinguishable from a slow one and the tunnel hangs
// until the caller's context expires; the bound turns it into an error a caller
// can act on (errors.Is) and a message that names the likely cause.
var ErrEdgeUnreachable = errors.New("edge unreachable")

// ErrHostnameUnresolved was the Err result of a tunnel whose hostname never
// resolved, back when readiness polled DNS and could give up. Readiness is
// now a fixed settle delay after the edge connection registers and produces
// no error; the variable remains so callers matching on it keep compiling.
var ErrHostnameUnresolved = errors.New("hostname unresolved")

// The environment variables, centralized: every code knob with an
// env-expressible value has a mirror here, and env beats code — an operator
// reconfigures a deployed binary without a rebuild. (The one exception is
// noted on LogEnv.) Each variable is read lazily, where its knob takes
// effect, so the pure-lazy contract holds.
const (
	// SpecEnv carries a JSON-encoded spec across a process boundary — the
	// parent→child handoff channel. A parent that mints a spec exports it
	// here; a child adopts it at construction and connects under the same
	// hostname and credentials. The value is a tagged envelope (the backend
	// that minted it plus its spec), so a child running a different backend
	// fails loudly. First in the credential chain: it beats FromEnv and a
	// code-pinned From spec.
	SpecEnv = "LIBTUNNEL_SPEC"
	// HostnameEnv is a plain-text mirror of the exported spec's hostname, set
	// alongside SpecEnv for tooling that wants the public hostname without
	// parsing the envelope. Export-only: libtunnel never adopts it.
	HostnameEnv = "LIBTUNNEL_HOSTNAME"
	// FromEnv replays a serialized spec by reference — hostname, file path,
	// or literal JSON, resolved exactly like libtunnel.From — as From's
	// environment mirror. Second in the credential chain: after SpecEnv,
	// before a code-pinned From spec and minting. An unresolvable or
	// foreign-backend reference is an error, not a fallthrough.
	FromEnv = "LIBTUNNEL_FROM"
	// LocalURLEnv overrides the local origin with a URL — WithLocalURL's
	// environment mirror. Consulted at origin-provide time (WithListener,
	// WithLocalURL, or a start-trigger mint), a set value supersedes whatever
	// the code provided. An unparsable or non-http(s) value cancels the
	// tunnel.
	LocalURLEnv = "LIBTUNNEL_LOCAL_URL"
	// TLSEnv fixes Backend.WithTLS from the environment
	// (strconv.ParseBool syntax): set, the mutator is a no-op. An unparsable
	// value fails the tunnel at connect.
	TLSEnv = "LIBTUNNEL_TLS"
	// HTTP2Env fixes Backend.WithHTTP2 from the environment, under the same
	// rules as TLSEnv.
	HTTP2Env = "LIBTUNNEL_HTTP2"
	// LogEnv names the level (debug|info|warn|error) of the default logger:
	// set, a tunnel with no WithLogger call logs to stderr at that level
	// instead of staying silent. The env-beats-code exception: an explicit
	// WithLogger keeps its handler — the environment carries a level, not a
	// sink. An unknown value reads as info, with a warning.
	LogEnv = "LIBTUNNEL_LOG"
	// CacheDirEnv overrides where minted specs are cached and where From and
	// Hosts look. Unset, a per-user location under os.UserCacheDir() is used.
	CacheDirEnv = "LIBTUNNEL_CACHE_DIR"
)

// The Cloudflare backend's variables, following the backend-scoped
// LIBTUNNEL__<BACKEND>_<FIELD> pattern (double underscore namespaces the
// backend). Each mirrors a spec-field setter on the Cloudflare backend —
// WithID, WithName, WithHostname, WithAccountTag, WithSecret — and env beats
// code, field by field, applied when the spec resolves: a complete credential
// set (id, hostname, account tag, secret) is a spec of its own and skips
// resolution, a partial one patches whatever the chain resolves.
const (
	// CloudflareEnv activates the Cloudflare backend in an env-only launcher
	// (cmd/libtunnel): set it to "1" to select Cloudflare when no spec
	// handoff is present. It follows the LIBTUNNEL__<BACKEND> switch pattern
	// (the backend name, no field suffix); future backends get their own
	// switch. The library's own New(Cloudflare()) path does not consult it —
	// it is the launcher's backend selector. LIBTUNNEL_SPEC also activates
	// Cloudflare, since the handoff envelope already names its backend.
	CloudflareEnv = "LIBTUNNEL__CLOUDFLARE"

	CloudflareIDEnv         = "LIBTUNNEL__CLOUDFLARE_ID"
	CloudflareNameEnv       = "LIBTUNNEL__CLOUDFLARE_NAME"
	CloudflareHostnameEnv   = "LIBTUNNEL__CLOUDFLARE_HOSTNAME"
	CloudflareAccountTagEnv = "LIBTUNNEL__CLOUDFLARE_ACCOUNT_TAG"
	// CloudflareSecretEnv carries the tunnel secret, base64-encoded (the
	// JSON []byte encoding); an undecodable value fails spec resolution.
	CloudflareSecretEnv = "LIBTUNNEL__CLOUDFLARE_SECRET"
	// CloudflareProviderEnv mirrors WithProvider: the quick-tunnel mint
	// provider host (default tunnel.pizza), from which the endpoint
	// https://<host>/tunnel is synthesized — though a value carrying a scheme
	// (://) is used verbatim. Only the mint path uses it.
	CloudflareProviderEnv = "LIBTUNNEL__CLOUDFLARE_PROVIDER"

	// CloudflareHeadersEnv mirrors WithHeader: request headers added to the
	// quick-tunnel mint call, a comma-separated K=V list (e.g. "X-Opaque=true").
	// Its entries beat code per key. Values cannot contain a comma or equals sign
	// — the list form has no escaping. Only the mint path uses it.
	CloudflareHeadersEnv = "LIBTUNNEL__CLOUDFLARE_HEADERS"

	// CloudflareEdgeEnv mirrors WithEdge: a comma-separated list of host:port
	// addresses to dial for the tunnel edge instead of discovering it by SRV
	// (which yields Cloudflare's edge on port 7844). Set, it also forces the
	// http2 edge protocol. Intended for a relay on an allowed port; see
	// WithEdge for the constraints.
	CloudflareEdgeEnv = "LIBTUNNEL__CLOUDFLARE_EDGE"
)

// Spec is the credential/identity set a Provider yields. Each backend defines
// a concrete spec type (cloudflare.Spec for the Cloudflare backend); the core
// only needs the public hostname the spec encodes — everything else is
// backend-internal.
type Spec interface {
	// GetHostname returns the public hostname (host or host:port) the tunnel
	// serves under.
	GetHostname() string
	// Serialize returns the spec as a tagged-envelope JSON string — the same
	// form carried by LIBTUNNEL_SPEC. The result round-trips through
	// libtunnel.From and can be dropped straight into the env var.
	Serialize() string
}

// Provider supplies a tunnel spec. Implementations may mint fresh credentials
// (a quick-tunnel API call) or replay existing ones (a static spec, a spec
// inherited from the environment). Spec blocks until credentials are
// available or ctx is done.
type Provider[T Spec] interface {
	Spec(ctx context.Context) (T, error)
}

// Backend selects the tunnel transport engine, fixes the spec type T, and
// supplies the credential chain specs are drawn from. Backends are opaque:
// obtain one from a façade constructor (libtunnel.Cloudflare()). The engine
// contract beyond these methods is alpha-internal — v1alpha1 type-asserts for
// its real interface — so custom Backend implementations outside this module
// are not supported.
type Backend[T Spec] interface {
	// Name identifies the backend (e.g. "cloudflare").
	Name() string
	// Provider is the credential chain this backend draws specs from. For
	// Cloudflare: adopt LIBTUNNEL_SPEC from the environment when present,
	// otherwise mint an anonymous quick tunnel.
	Provider() Provider[T]
	// WithTLS declares whether the local origin terminates TLS. True dials the
	// listener over https (verification is off, so a self-signed cert is fine);
	// false over http. Default false. Chainable:
	// libtunnel.Cloudflare().WithTLS(true). The LIBTUNNEL_TLS environment
	// variable (strconv.ParseBool syntax) fixes the knob at backend
	// construction and makes this call a no-op — env beats code; an
	// unparsable value fails the tunnel at connect.
	WithTLS(bool) Backend[T]
	// WithHTTP2 declares whether the origin is dialed over HTTP/2 rather than
	// HTTP/1.1. Independent of WithTLS, though a stdlib http.Server only
	// negotiates HTTP/2 over TLS. Default false. Chainable. LIBTUNNEL_HTTP2
	// fixes it from the environment under the same rules as WithTLS.
	WithHTTP2(bool) Backend[T]
	// Reconnect forcefully cycles the engine's connection(s) to the tunnel edge
	// and blocks until the edge is re-established or ctx is done (returning
	// ctx.Err()); pass a ctx with a deadline to bound the wait. It also returns
	// if the tunnel itself shuts down while waiting. It is an error to call
	// before the tunnel has connected. This is the same lever surfaced to
	// interceptors as InterceptCtx.Reconnect.
	Reconnect(ctx context.Context) error
}

// Tunnel is the lazy tunnel handle returned by libtunnel.New. All getters
// resolve on first use; getters that need state that is not yet available
// block until it is (or until the tunnel is canceled), in which case they
// return zero values. The edge connection starts on first demand: the origin
// is provided exactly once — WithListener provides it as a listener,
// WithLocalURL as the URL of an already-running local service, and the start
// triggers — Listener, URL, TunnelReady — mint a loopback listener if no
// origin was provided. Providing an origin twice, by any combination of
// those, cancels the tunnel (Err reports "origin already provided").
//
// Configuration is write-once: each With* mutator takes effect at most once
// and is a no-op after its value is fixed, whether by an earlier call or by
// the tunnel's first use of the default.
//
// It is non-generic: the backend spec type is a construction-time detail that
// does not outlive New, so callers can store a tunnel reference without
// threading the spec type through their own code.
type Tunnel interface {
	// LocalPort is the origin's local port: the listener's bound port, or for
	// a URL origin (WithLocalURL) the URL's port — 443 for https and 80 for
	// http when the URL has none. Blocks until an origin is provided.
	LocalPort() int
	// LocalIP is the origin's local IP: the listener's bound IP, or for a URL
	// origin the URL's host, parsed as an IP or resolved. A listener bound to
	// an unspecified address (0.0.0.0 / ::) falls back to the outbound-route
	// IP, discovered with a UDP dial that sends no packets. Blocks until an
	// origin is provided.
	LocalIP() net.IP
	// LocalHost is the machine's hostname, truncated at the first dot.
	LocalHost() string
	// LocalURL is the local origin's URL: http://<LocalIP>:<LocalPort>/ for a
	// listener origin (always http — the origin's scheme is a backend
	// setting, WithTLS, and the public URL carries the real scheme), or the
	// provided URL itself for a URL origin, scheme intact. Blocks until an
	// origin is provided.
	LocalURL() *url.URL

	// Host is the first label of Hostname.
	Host() string
	// Hostname is the public hostname from the spec.
	Hostname() string
	// Domain is Hostname with the first label removed.
	Domain() string
	// Port is the port encoded in Hostname, or 443 when absent.
	Port() int
	// CACerts returns the trust roots the backend uses for its edge
	// connections.
	CACerts() []*x509.Certificate

	// Listener returns a tunnel-owned listener to serve on, starting the edge
	// connection on first use. With a listener provided via WithListener it
	// returns a tunnel-owned view of that one; with no origin provided it
	// mints a loopback listener (127.0.0.1:0) and adopts it, so
	// http.Serve(tun.Listener(), h) needs no net.Listen of your own.
	// Idempotent: repeated calls return the same listener. A URL origin
	// (WithLocalURL) has no listener: calling Listener then cancels the
	// tunnel and returns nil.
	//
	// Closing it closes the tunnel (Done fires, Err reports ErrClosed) — so an
	// http.Server serving on it tears the tunnel down on Shutdown/Close. To
	// restart the origin while the tunnel persists, close the original
	// listener handed to WithListener instead and rebind the same address; a
	// minted listener has no separate owner, so closing it is terminal.
	Listener() net.Listener
	// URL is https://<Hostname>/. It blocks until the hostname is expected
	// to resolve publicly (see HostnameReady). URL demands public
	// reachability, so like Listener it is a start trigger: with no origin
	// provided it mints a loopback listener and starts the edge connection,
	// instead of waiting on readiness that could never arrive.
	URL() *url.URL

	// HostnameReady is closed once the hostname is expected to resolve
	// publicly: a settle delay after the edge connection registers, waiting
	// out the record's spread across the zone's nameservers. Nothing on this
	// machine is asked about the hostname before then.
	HostnameReady() <-chan struct{}
	// TunnelReady is closed when the edge connection is up and the hostname
	// resolves publicly — the tunnel is reachable end to end. It is never
	// closed on failure: select on Done alongside it. Like URL it is a start
	// trigger: with no origin provided it mints a loopback listener and
	// starts the edge connection before handing back the channel.
	TunnelReady() <-chan struct{}
	// Done is closed when the tunnel fails or shuts down. Waits on TunnelReady
	// or HostnameReady should select on Done too, or a failed tunnel blocks
	// them forever.
	Done() <-chan struct{}
	// Err reports why the tunnel ended (nil while it is alive).
	Err() error

	// WithLogger sets the logger, once. Unset, the tunnel is silent — unless
	// the LIBTUNNEL_LOG environment variable names a level
	// (debug|info|warn|error); then the default logs to stderr at that level.
	// An explicit WithLogger keeps its handler either way: the environment
	// carries a level, not a sink.
	WithLogger(log *slog.Logger) Tunnel
	// WithContext threads a caller context into the tunnel, once. It does two
	// things. First, URL waits for the tunnel to be reachable end to end
	// (TunnelReady), honoring the context, instead of only for the hostname to
	// resolve — and returns nil if the context is done first. Unset (or nil),
	// URL waits on DNS alone. Second, the context is the tunnel's shutdown
	// handle: canceling it tears the tunnel down (Done fires, Err reports the
	// context's cause) — the teardown a WithLocalURL origin otherwise lacks.
	WithContext(ctx context.Context) Tunnel
	// WithListener provides the local origin as a listener and lazily starts
	// the edge connection. The origin scheme is not inferred from the
	// listener — declare it on the backend with WithTLS / WithHTTP2 (both
	// default false).
	//
	// The origin is provided exactly once, shared with WithLocalURL and the
	// start-trigger mint. Providing it again — a second WithListener or
	// WithLocalURL, or either after a start trigger (Listener, URL,
	// TunnelReady) minted a listener — cancels the tunnel (Err reports
	// "origin already provided"). To let the tunnel supply the listener
	// instead, skip WithListener and call Listener().
	//
	// The LIBTUNNEL_LOCAL_URL environment variable supersedes any provide —
	// this listener, a WithLocalURL argument, or the start-trigger mint: env
	// beats code, so an operator can redirect a deployed binary's origin
	// without a rebuild. The override makes the origin a URL, with everything
	// that implies (see WithLocalURL); an invalid value cancels the tunnel.
	WithListener(l net.Listener) Tunnel
	// WithLocalURL provides the local origin as the URL of an already-running
	// local service (e.g. http://localhost:1234) and lazily starts the edge
	// connection — the cloudflared `tunnel --url` shape. Only the scheme and
	// host are used: the scheme (http or https) declares how the origin is
	// dialed, superseding the backend's WithTLS (which applies to listener
	// origins only), and anything else (path, query, user info) is dropped. A
	// nil URL, a scheme other than http/https, or an empty host cancels the
	// tunnel.
	//
	// The origin is provided exactly once — see WithListener, including the
	// LIBTUNNEL_LOCAL_URL environment override, which supersedes this
	// argument too. A URL origin has no tunnel-owned listener: Listener must
	// not be called (it cancels the tunnel), and Close is not the teardown
	// path. To shut a URL-origin tunnel down, set a context with WithContext
	// and cancel it; otherwise it runs until the process exits or the tunnel
	// fails.
	WithLocalURL(u *url.URL) Tunnel

	// WithInterceptor registers an Interceptor (a Match predicate paired with an
	// InterceptFn) in front of the in-process reverse proxy that fronts the
	// origin. For every inbound request the tunnel walks its interceptors in
	// registration order and runs the first whose Match returns true; requests
	// that match none are proxied to the origin unchanged. May be called more
	// than once to layer interceptors, and may be called after the tunnel is
	// live. Bundling the pair in one value lets callers ship reusable
	// interceptors as constructors — tun.WithInterceptor(addHeaders()). Returns
	// the tunnel for chaining.
	WithInterceptor(interceptor Interceptor) Tunnel

	// Interceptors returns a snapshot of the registered interceptors in
	// precedence order — ascending Priority, ties in registration order, the
	// order requests are matched against. Any auto-assigned Priority (from a
	// zero-Priority registration) is resolved in the returned values, for
	// visibility into the effective ordering.
	Interceptors() Interceptors
}

// MatchFn reports whether an interceptor applies to a request. It runs on the
// proxy goroutine for every inbound request, so it must be fast and must not
// mutate r.
type MatchFn = func(r *http.Request) bool

// InterceptCtx is the per-request handle passed to an interceptor. It embeds the
// request's context.Context (so it carries deadlines and cancellation and can be
// passed anywhere a context is wanted), exposes the request and response writer,
// and carries the handler that will serve the request — seeded to proxy the
// origin. An interceptor shapes the response by calling WithHandler, and reaches
// past the single request through the tunnel-level levers (Reconnect, Target).
type InterceptCtx interface {
	context.Context

	// Reconnect forcefully cycles the engine's edge connection(s) and blocks
	// until re-established or ctx is done (see Backend.Reconnect).
	Reconnect(ctx context.Context) error
	// Target is the loopback listener the engine dials to reach the origin
	// proxy — the proxy's own accept socket, not the origin. An interceptor can
	// cycle it (close to force the engine to re-dial).
	Target() net.Listener

	// WithHandler replaces the handler that will serve this request and returns
	// the ctx for chaining. Unset, the handler proxies the request to the origin.
	WithHandler(h http.HandlerFunc) InterceptCtx
	// Handler is the handler currently set to serve the request.
	Handler() http.HandlerFunc

	// Writer is the response writer for the request.
	Writer() http.ResponseWriter
	// Request is the inbound request.
	Request() *http.Request
}

// InterceptFn shapes how a matched request is served. It receives the request's
// InterceptCtx — request, response writer, embedded context, and tunnel levers —
// and returns a ctx whose Handler serves the request, typically the same ctx
// after a WithHandler call. Returning the ctx unchanged (or nil) keeps the
// default: the request is proxied to the origin, just as if nothing had matched.
// So an interceptor can match broadly, inspect, and opt out per request.
type InterceptFn = func(ctx InterceptCtx) InterceptCtx

// Interceptor pairs a match predicate with the handler it selects.
type Interceptor struct {
	Match   MatchFn
	Handler InterceptFn
	// Priority orders interceptors when more than one could match, AWS-ALB style:
	// the LOWEST Priority is consulted first, so it wins. Interceptors of equal
	// Priority keep registration order.
	//
	// 0 is not a precedence — it is the zero value that means "unset". An unset
	// Priority is auto-assigned from the top of the uint16 range downward, so
	// unprioritized interceptors sit at the low-precedence end: a later-registered
	// one wins over an earlier one, and any interceptor given an explicit Priority
	// outranks them all.
	//
	// So 1 is the highest settable precedence and 65535 the lowest; larger =
	// lower precedence. To pin an interceptor above every default, give it a
	// small Priority (1); to make it a fallback, a large one.
	Priority uint16
}

// Interceptors is the registry consulted per request, in precedence order: the
// lowest-Priority Interceptor whose Match returns true wins (1 is highest, larger
// is lower), ties broken by registration order. Priority 0 means unset — those
// interceptors are auto-assigned from the top of the range down, so among them
// the later-registered wins.
type Interceptors = []Interceptor
