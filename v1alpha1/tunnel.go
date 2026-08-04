package v1alpha1

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1/resolver"
)

// WithLogger sets the logger, once: the first call wins, and a nil logger is
// ignored. A no-op after the log field is fixed — by an earlier WithLogger,
// or by the tunnel's first internal Logger read fixing the default (silent,
// or a stderr logger when v1.LogEnv is set).
func (t *TunnelImpl[T]) WithLogger(log *slog.Logger) v1.Tunnel {
	if log != nil {
		t.logOnce.Do(func() {
			t.log = log
		})
	}
	return t
}

// WithContext threads a caller context into the tunnel: once set, URL upgrades
// from "the hostname resolves" to "the tunnel is reachable end to end" — it
// waits for TunnelReady, honoring this context, and returns nil if the context
// is done first. It is also the tunnel's shutdown handle: canceling the
// context tears the tunnel down (Done fires, Err reports the context's cause),
// which is the only teardown a WithLocalURL origin has. Write-once: the first
// call wins, a nil ctx is ignored, and a URL call that already fixed the field
// (to nil, unset) makes this a no-op.
func (t *TunnelImpl[T]) WithContext(ctx context.Context) v1.Tunnel {
	if ctx != nil {
		t.userCtxOnce.Do(func() {
			t.userCtx = ctx
			// Propagate cancellation into the engine context so the caller's
			// context is a real shutdown handle, not just a cap on URL's wait.
			// The watcher retires when either context ends, so it never leaks.
			go func() {
				select {
				case <-ctx.Done():
					t.cancel(context.Cause(ctx))
				case <-t.ctx.Done():
				}
			}()
		})
	}
	return t
}

// WithListener provides the local origin as a listener and lazily starts the
// edge connection. The listener is the single source of local-side truth:
// LocalIP, LocalPort, and LocalURL all derive from its address.
//
// The origin is provided exactly once, shared with WithLocalURL and the
// start-trigger mint. Providing it again — a second WithListener or
// WithLocalURL, or either after a start trigger (Listener, URL, TunnelReady)
// already minted one — cancels the tunnel (Err reports "origin already
// provided"). As an alternative to bringing your own, call Listener() to have
// the tunnel mint a loopback listener for you.
func (t *TunnelImpl[T]) WithListener(l net.Listener) v1.Tunnel {
	provided := false
	t.originOnce.Do(func() {
		provided = true
		if t.provideFromEnv() {
			return
		}
		t.provide(l, false)
	})
	if !provided {
		t.cancel(fmt.Errorf("WithListener: origin already provided"))
	}
	return t
}

// autoPriorityStep is how far the auto lane steps down per interceptor
// registered with Priority 0 (unset). The counter starts at math.MaxUint16, so
// unprioritized interceptors sit at the low-precedence end and a later-registered
// one steps toward higher precedence — later wins.
const autoPriorityStep = 10

// nextAutoPriority returns the next auto-assigned Priority, stepping the counter
// down by autoPriorityStep and saturating at 0 (its minimum) rather than
// underflowing the unsigned counter.
func (t *TunnelImpl[T]) nextAutoPriority() uint16 {
	for {
		cur := t.autoPriority.Load()
		var next uint32
		if cur > autoPriorityStep {
			next = cur - autoPriorityStep
		}
		if t.autoPriority.CompareAndSwap(cur, next) {
			return uint16(next)
		}
	}
}

// WithInterceptor registers an interceptor, keeping the registry ordered by
// ascending Priority (ties in registration order) so Intercept's first-match
// scan yields the lowest-Priority — highest-precedence — match. A Priority of 0
// (unset) is auto-assigned from the top of the range downward, so later-
// registered unprioritized interceptors win and any explicit Priority outranks
// them. The stable sort preserves insertion order for equal Priorities. Safe to
// call concurrently and after the tunnel is live (see v1.Tunnel.WithInterceptor).
func (t *TunnelImpl[T]) WithInterceptor(interceptor v1.Interceptor) v1.Tunnel {
	if interceptor.Priority == 0 {
		interceptor.Priority = t.nextAutoPriority()
	}
	t.interceptorsMu.Lock()
	defer t.interceptorsMu.Unlock()
	t.interceptors = append(t.interceptors, interceptor)
	sort.SliceStable(t.interceptors, func(i, j int) bool {
		return t.interceptors[i].Priority < t.interceptors[j].Priority
	})
	return t
}

// Interceptors returns a snapshot of the registry in precedence order (ascending
// Priority, ties in registration order) — the order Intercept consults them.
// It's a defensive copy: mutating the returned slice does not affect the live
// registry (Interceptor is a value type; its func fields are immutable
// references). If Interceptor ever gains a reference-type field, deep-copy it here.
func (t *TunnelImpl[T]) Interceptors() v1.Interceptors {
	t.interceptorsMu.Lock()
	defer t.interceptorsMu.Unlock()
	out := make(v1.Interceptors, len(t.interceptors))
	copy(out, t.interceptors)
	return out
}

// Intercept resolves the handler for a request through the interceptor
// registry. The lowest-Priority (highest-precedence) interceptor whose Match
// returns true runs (ties by registration order — the registry is kept sorted),
// given the InterceptCtx (which carries the request and the default origin-proxy
// handler); it shapes the response by calling ctx.WithHandler and returns the
// ctx. When nothing matches — or an interceptor returns nil — the ctx's default
// handler (proxy to the origin) stands. The registry lock is held only across
// the match scan, not the interceptor. The returned handler is the one the
// engine serves.
func (t *TunnelImpl[T]) Intercept(ctx v1.InterceptCtx) http.HandlerFunc {
	t.interceptorsMu.Lock()
	var interceptor v1.InterceptFn
	for _, item := range t.interceptors {
		if item.Match(ctx.Request()) {
			interceptor = item.Handler
			break
		}
	}
	t.interceptorsMu.Unlock()

	if interceptor == nil {
		return ctx.Handler()
	}
	if out := interceptor(ctx); out != nil {
		return out.Handler()
	}
	return ctx.Handler()
}

// WithLocalURL provides the local origin as the URL of an already-running
// local service and lazily starts the edge connection — the cloudflared
// `tunnel --url` shape. Only the scheme and host are kept: the scheme (http
// or https) declares how the origin is dialed, superseding the backend's
// WithTLS, and path/query/user info are dropped. A nil URL, a scheme other
// than http/https, or an empty host cancels the tunnel.
//
// The origin is provided exactly once, shared with WithListener and the
// start-trigger mint (see WithListener).
func (t *TunnelImpl[T]) WithLocalURL(u *url.URL) v1.Tunnel {
	provided := false
	t.originOnce.Do(func() {
		provided = true
		if t.provideFromEnv() {
			return
		}
		normalized, err := normalizeLocalURL(u)
		if err != nil {
			t.cancel(fmt.Errorf("WithLocalURL: %w", err))
			return
		}
		t.provideURL(normalized)
	})
	if !provided {
		t.cancel(fmt.Errorf("WithLocalURL: origin already provided"))
	}
	return t
}

// normalizeLocalURL validates a local origin URL and reduces it to
// scheme+host+"/" — the form provideURL and the engines consume. Shared by
// WithLocalURL and the v1.LocalURLEnv override.
func normalizeLocalURL(u *url.URL) (*url.URL, error) {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("origin must be an http(s) URL with a host, got %v", u)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"}, nil
}

// provideFromEnv applies the v1.LocalURLEnv override: set, it provides the
// origin from the environment — superseding whatever the caller was about to
// provide — and reports true. An invalid value also reports true, with the
// tunnel canceled: the provide slot is spent either way. Unset, it reports
// false and the caller provides as usual. Runs inside originOnce.Do.
func (t *TunnelImpl[T]) provideFromEnv() bool {
	env, ok := os.LookupEnv(v1.LocalURLEnv)
	if !ok || env == "" {
		return false
	}
	parsed, err := url.Parse(env)
	if err == nil {
		parsed, err = normalizeLocalURL(parsed)
	}
	if err != nil {
		t.cancel(fmt.Errorf("%s: %w", v1.LocalURLEnv, err))
		return true
	}
	t.Logger().Info("local origin overridden from the environment", "var", v1.LocalURLEnv, "url", parsed.String())
	t.provideURL(parsed)
	return true
}

// provide adopts l as the local origin and starts the edge connection. It
// runs inside the caller's originOnce.Do, so exactly once. minted
// marks a listener the tunnel owns (created by a start trigger), which is
// closed when the tunnel ends; a caller-provided listener stays caller-owned.
func (t *TunnelImpl[T]) provide(l net.Listener, minted bool) {
	t.Logger().Info("configuring tunnel with local listener", "address", l.Addr().String(), "minted", minted)
	t.listener = l
	close(t.originProvided)

	if minted {
		// The tunnel owns a minted listener; close it when the tunnel ends so a
		// canceled tunnel doesn't leak the bound port.
		go func() {
			<-t.ctx.Done()
			l.Close()
		}()
	}

	t.start(func() error { return t.engine.WithListener(t, l) })
}

// provideURL adopts u (already validated and reduced to scheme+host+"/") as
// the local origin and starts the edge connection — provide's counterpart for
// URL origins. It runs inside the caller's originOnce.Do, so exactly once.
func (t *TunnelImpl[T]) provideURL(u *url.URL) {
	t.Logger().Info("configuring tunnel with local origin URL", "url", u.String())
	t.localURL = u
	close(t.originProvided)

	t.start(func() error { return t.engine.WithLocalURL(t, u) })
}

// start runs the connect sequence in the background: kick off the DNS
// readiness poller (it waits on hostnameProvided) and mint the spec, both
// before the edge connect — the record exists from spec-mint time, so DNS
// propagation overlaps the (seconds-long) edge dial instead of queuing behind
// it — then dial the edge via connect (which blocks until the connection is
// up) and close tunnelReady once DNS readiness lands too. On a foreign
// resolverFactory builds the resolver used for hostname readiness.
type resolverFactory = func() resolver.Resolver

// newResolver holds that constructor as a swappable hook. It is atomic because
// tests replace it (SetResolver) while background start goroutines from other
// tests may still be reading it — production only reads it, set once here.
var newResolver = func() *atomic.Pointer[resolverFactory] {
	var p atomic.Pointer[resolverFactory]
	fn := resolverFactory(resolver.NewResolver)
	p.Store(&fn)
	return &p
}()

// backend (nil engine, tunnel born canceled — see New) it does nothing.
func (t *TunnelImpl[T]) start(connect func() error) {
	if t.engine == nil {
		return
	}

	go func() {
		t.Logger().Info("starting tunnel")
		t.Spec()
		if err := connect(); err != nil {
			t.cancel(fmt.Errorf("backend %q connect: %w", t.engine.Name(), err))
			return
		}

		t.Logger().Info("tunnel connected, waiting for DNS")
		rec := (*newResolver.Load())().Resolve(t.Hostname())
		t.markHostnameReady(t.Hostname(), rec)

		t.Logger().Info("tunnel is ready")
		close(t.tunnelReady)
	}()
}

// Listener returns a tunnel-owned listener to serve on. If a listener was
// provided via WithListener it returns a tunnel-owned view of that one;
// otherwise it mints a loopback listener (127.0.0.1:0), adopts it as
// WithListener would — same edge-connect and DNS-readiness path — and the
// tunnel owns it (closed on shutdown). Idempotent: repeated calls return the
// same listener.
//
// Closing the returned listener closes the tunnel. A caller-provided listener
// stays caller-owned, so closing that restarts the origin while the tunnel
// persists; a minted one has no separate owner, so closing it is terminal.
func (t *TunnelImpl[T]) Listener() net.Listener {
	t.ensureOrigin()
	if t.originURL() != nil {
		t.cancel(fmt.Errorf("Listener: the origin is a URL (WithLocalURL); no listener exists"))
		return nil
	}
	return t.boundListener()
}

// ensureOrigin is the shared start-trigger step behind Listener, URL, and
// TunnelReady: with no origin provided yet it adopts the v1.LocalURLEnv override
// when set, else mints a loopback listener (127.0.0.1:0) and adopts that;
// with an origin already provided — listener or URL — it is a no-op.
func (t *TunnelImpl[T]) ensureOrigin() {
	t.originOnce.Do(func() {
		if t.provideFromEnv() {
			return
		}
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			// boundListener below sees the canceled tunnel and returns nil.
			t.cancel(fmt.Errorf("unable to mint a local listener: %w", err))
			return
		}
		t.provide(l, true)
	})
}

// originURL blocks until an origin is provided and returns the URL it was
// provided as — nil for a listener origin, or for a tunnel canceled first.
// The local-side getters branch on it before touching the listener.
func (t *TunnelImpl[T]) originURL() *url.URL {
	// The localURL field is only safe to read once originProvided is closed
	// (the close is the happens-before edge for the write), so a cancellation
	// wake returns nil instead of reading the field.
	if !await(t.ctx, t.originProvided) {
		return nil
	}
	return t.localURL
}

// boundListener blocks until a listener is provided (via WithListener or a
// start-trigger mint) and returns a tunnel-owned view of it, or nil if the
// tunnel is canceled first or the origin is a URL. It never mints — the
// local-side getters use it so observing the bind address can't start a
// tunnel.
func (t *TunnelImpl[T]) boundListener() net.Listener {
	// The listener field is only safe to read once originProvided is closed
	// (the close is the happens-before edge for the write), so a cancellation
	// wake returns nil instead of reading the field.
	if !await(t.ctx, t.originProvided) {
		return nil
	}
	if t.listener == nil {
		// URL origin: there is no listener to view.
		return nil
	}
	return tunnelListener[T]{Listener: t.listener, t: t}
}

// tunnelListener ties the tunnel's lifetime to the listener handle handed to
// callers: an http.Server shutting down on it tears the tunnel down too.
type tunnelListener[T v1.Spec] struct {
	net.Listener
	t *TunnelImpl[T]
}

func (l tunnelListener[T]) Close() error {
	l.t.cancel(v1.ErrClosed)
	return l.Listener.Close()
}

// LocalPort is the origin's local port: the listener's bound port, or for a
// URL origin the URL's port — 443 for https and 80 for http when the URL has
// none. Blocks until an origin is provided.
func (t *TunnelImpl[T]) LocalPort() int {
	if u := t.originURL(); u != nil {
		if p, err := strconv.Atoi(u.Port()); err == nil {
			return p
		}
		if u.Scheme == "https" {
			return 443
		}
		return 80
	}
	l := t.boundListener()
	if l == nil {
		return 0
	}
	if addr, ok := l.Addr().(*net.TCPAddr); ok {
		return addr.Port
	}
	// Exotic listener: fall back to parsing the address string.
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.cancel(fmt.Errorf("unable to determine local port from listener address %q: %w", l.Addr(), err))
		return 0
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.cancel(fmt.Errorf("unable to parse local port from listener address %q: %w", l.Addr(), err))
		return 0
	}
	return p
}

// LocalIP is the origin's local IP: the listener's bound IP, or for a URL
// origin the URL's host, parsed as an IP or resolved. An unspecified address
// (0.0.0.0 / ::) has no concrete IP to report, so it falls back to the
// outbound-route IP, discovered with a UDP dial (no packets are sent).
// Blocks until an origin is provided.
func (t *TunnelImpl[T]) LocalIP() net.IP {
	t.localIPOnce.Do(func() {
		var ip net.IP
		if u := t.originURL(); u != nil {
			host := u.Hostname()
			ip = net.ParseIP(host)
			if ip == nil {
				addrs, err := net.DefaultResolver.LookupIPAddr(t.ctx, host)
				if err != nil || len(addrs) == 0 {
					t.cancel(fmt.Errorf("unable to resolve local origin host %q: %w", host, err))
					return
				}
				ip = addrs[0].IP
			}
		} else {
			l := t.boundListener()
			if l == nil {
				return
			}
			if addr, ok := l.Addr().(*net.TCPAddr); ok {
				ip = addr.IP
			} else {
				// Exotic listener: fall back to parsing the address string.
				host, _, err := net.SplitHostPort(l.Addr().String())
				if err != nil {
					t.cancel(fmt.Errorf("unable to determine local IP from listener address %q: %w", l.Addr(), err))
					return
				}
				ip = net.ParseIP(host)
			}
		}
		if ip != nil && !ip.IsUnspecified() {
			t.localIP = ip
			return
		}

		t.Logger().Info("origin bound to unspecified address, determining outbound-route IP")
		conn, err := net.Dial("udp", "1.1.1.1:53")
		if err != nil {
			t.cancel(fmt.Errorf("unable to get local IP: %w", err))
			return
		}
		defer conn.Close()
		t.localIP = conn.LocalAddr().(*net.UDPAddr).IP
		t.Logger().Info("determined local IP for tunnel", "localIP", t.localIP.String())
	})
	return t.localIP
}

// LocalHost is the machine's hostname, truncated at the first dot.
func (t *TunnelImpl[T]) LocalHost() string {
	t.localHostOnce.Do(func() {
		hostname, err := os.Hostname()
		if err != nil {
			t.cancel(fmt.Errorf("unable to get local hostname: %w", err))
			return
		}
		hostname, _, _ = strings.Cut(hostname, ".")
		t.localHost = hostname
	})
	return t.localHost
}

// LocalURL is the local origin's URL. For a listener origin it is
// http://<LocalIP>:<LocalPort>/ — always http: the origin's scheme is a
// backend setting (WithTLS), not derived here, and the public URL carries the
// real scheme. For a URL origin it is the provided URL itself, scheme intact.
// Blocks until an origin is provided.
func (t *TunnelImpl[T]) LocalURL() *url.URL {
	if u := t.originURL(); u != nil {
		clone := *u
		return &clone
	}
	ip := t.LocalIP()
	if ip == nil {
		return nil
	}
	return &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(ip.String(), strconv.Itoa(t.LocalPort())),
		Path:   "/",
	}
}

// Spec returns the resolved tunnel spec, fetching it from the backend's
// provider chain on first use.
func (t *TunnelImpl[T]) Spec() T {
	t.specOnce.Do(func() {
		if t.backend == nil {
			// A placeholder tunnel (Failed) has no backend and is already
			// canceled; there is nothing to resolve.
			return
		}
		provider := t.backend.Provider()
		// Providers that can log (retry warnings, rate limits) pick up the
		// tunnel's logger here — they're built by the backend before any
		// WithLogger call, so the logger is threaded late.
		if pl, ok := provider.(LoggerSetter); ok {
			pl.SetLogger(t.Logger())
		}

		t.Logger().Info("fetching tunnel spec")
		spec, err := provider.Spec(t.ctx)
		if err != nil {
			// Log synchronously: the async cancel watcher may lose the race
			// against a caller that exits on the zero value.
			t.Logger().Error("unable to fetch tunnel spec", "error", err)
			t.cancel(fmt.Errorf("unable to fetch tunnel spec: %w", err))
			return
		}
		t.spec = spec
		t.Logger().Info("fetched tunnel spec", "hostname", spec.GetHostname())
		// The public hostname is now known; release the authoritative poll
		// (started by WithListener) so DNS propagation overlaps the edge dial.
		close(t.hostnameProvided)
	})
	return t.spec
}

// Hostname is the public hostname from the spec.
func (t *TunnelImpl[T]) Hostname() string {
	return t.Spec().GetHostname()
}

// Host is the first label of Hostname.
func (t *TunnelImpl[T]) Host() string {
	return hostOf(t.Hostname())
}

// Domain is Hostname with the first label removed.
func (t *TunnelImpl[T]) Domain() string {
	return domainOf(t.Hostname())
}

// Port is the port encoded in Hostname, or 443 when absent.
func (t *TunnelImpl[T]) Port() int {
	return portOf(t.Hostname())
}

// URL is https://<Hostname>/. It blocks until the hostname resolves on the
// zone's authoritative nameservers. Returns nil if the tunnel is canceled
// before that happens, per the v1 contract's zero-value-on-cancel rule.
//
// URL demands public reachability, so like Listener it is a start trigger:
// with no origin provided it mints a loopback listener and starts the edge
// connection, instead of waiting on readiness that could never arrive.
func (t *TunnelImpl[T]) URL() *url.URL {
	// Ensure the tunnel is starting before waiting on it. Origin first, then
	// Hostname: provide kicks off the spec fetch in the background, so the
	// edge dial and DNS propagation overlap the Hostname wait.
	t.ensureOrigin()
	hostname := t.Hostname()

	// Fix the userCtx field before reading it: an unset field freezes to nil
	// (URL waits on DNS alone), and a later WithContext becomes a no-op
	// instead of a mutation under this read.
	t.userCtxOnce.Do(func() {})
	if t.userCtx != nil {
		// A caller context set via WithContext upgrades URL from "the hostname
		// resolves" to "the tunnel is reachable end to end": wait for
		// TunnelReady (which implies the hostname has resolved), honoring both
		// the tunnel's lifetime and the caller's context. A raw three-way
		// select on purpose — it waits on two cancellation sources, which the
		// single-ctx await helper does not model.
		select {
		case <-t.TunnelReady():
		case <-t.ctx.Done():
			return nil
		case <-t.userCtx.Done():
			return nil
		}
	} else if !await(t.ctx, t.HostnameReady()) {
		return nil
	}

	return &url.URL{
		Scheme: "https",
		Host:   hostname,
		Path:   "/",
	}
}

// CACerts returns the backend's trust roots for its edge connections.
func (t *TunnelImpl[T]) CACerts() []*x509.Certificate {
	t.caCertsOnce.Do(func() {
		if t.engine == nil {
			// Foreign backend: the tunnel was born canceled (see New).
			return
		}
		t.caCerts = t.engine.CACerts()
		t.Logger().Info("loaded CA certificates for tunnel", "numCACerts", len(t.caCerts))
	})
	return t.caCerts
}

// TunnelReady is closed when the edge connection is up and the hostname
// resolves publicly. Waiting on readiness demands a running tunnel, so like
// URL it is a start trigger: with no origin provided it mints a loopback
// listener and starts the edge connection before handing back the channel.
func (t *TunnelImpl[T]) TunnelReady() <-chan struct{} {
	t.ensureOrigin()
	return t.tunnelReady
}

// HostnameReady returns the channel closed once the public hostname resolves on
// the zone's authoritative nameservers. The poll that closes it is started by
// WithListener and gated on hostnameProvided, so this is a pure accessor —
// select on it (and on Done).
//
// Readiness is authoritative-only: pollAuthoritative queries the zone's
// nameservers directly (the dig equivalent, via package resolver) and fires as
// soon as one of them serves a non-empty A+AAAA set — a record on any
// authoritative nameserver, never a recursive resolver's cache. Queries are
// RD=1 (the quick-tunnel nameservers REFUSE RD=0).
func (t *TunnelImpl[T]) HostnameReady() <-chan struct{} {
	return t.hostnameReady
}

// markHostnameReady logs the resolved record and closes the readiness channel.
// One caller (pollAuthoritative) reaches it once, so the close needs no guard.
func (t *TunnelImpl[T]) markHostnameReady(host string, rec resolver.Records) {
	t.Logger().Info("hostname resolved", "hostname", host, "A", rec.A, "AAAA", rec.AAAA)
	close(t.hostnameReady)
}

// hostOf returns the first label of hostname.
func hostOf(hostname string) string {
	host, _, _ := strings.Cut(hostname, ".")
	return host
}

// domainOf returns hostname with the first label removed.
func domainOf(hostname string) string {
	_, domain, _ := strings.Cut(hostname, ".")
	return domain
}

// await blocks until ch yields or ctx is done, whichever comes first, and
// reports whether ch yielded. It is the one place blocked getters wait, so
// cancellation semantics aren't re-derived select-by-select at every call
// site: every wait stops naturally on context cancel, and the return value
// says whether the awaited state actually arrived (false ⇒ the getter owes
// its caller a zero value). When both channels are ready it prefers ch, so
// state that landed just before cancellation still reads as delivered.
func await[E any](ctx context.Context, ch <-chan E) bool {
	select {
	case <-ch:
		return true
	default:
	}
	select {
	case <-ch:
		return true
	case <-ctx.Done():
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}
}

// dnsName strips any :port from hostname: DNS queries take bare names, while
// the v1 contract allows GetHostname to carry host:port.
func dnsName(hostname string) string {
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		return host
	}
	return hostname
}

// portOf returns the port encoded in hostname, or 443 when absent, unparsable,
// or out of range.
func portOf(hostname string) int {
	_, port, err := net.SplitHostPort(hostname)
	if err != nil {
		return 443
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return 443
	}
	return p
}
