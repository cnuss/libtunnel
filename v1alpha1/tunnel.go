package v1alpha1

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1/resolver"
)

// WithLogger sets the logger. A no-op once a listener has been provided.
func (t *TunnelImpl[T]) WithLogger(log *slog.Logger) v1.Tunnel {
	select {
	case <-t.listenerProvided:
	default:
		if log != nil {
			t.log.Store(log)
		}
	}
	return t
}

// WithContext threads a caller context into URL: once set, URL upgrades from
// "the hostname resolves" to "the tunnel is reachable end to end" — it waits
// for TunnelReady, honoring this context, and returns nil if the context is
// done first. A no-op once a listener has been provided, or if ctx is nil.
func (t *TunnelImpl[T]) WithContext(ctx context.Context) v1.Tunnel {
	select {
	case <-t.listenerProvided:
	default:
		if ctx != nil {
			t.userCtx.Store(&ctx)
		}
	}
	return t
}

// WithListener provides the local listener and lazily starts the edge
// connection. The listener is the single source of local-side truth: LocalIP,
// LocalPort, and LocalURL all derive from its address. The returned
// v1.Tunneled carries no mutators — there is nothing left to configure.
//
// The listener is provided exactly once. Providing it again — a second
// WithListener, or WithListener after Listener() already minted one — cancels
// the tunnel (Err reports "listener already provided"). As an alternative to
// bringing your own, call Listener() to have the tunnel mint a loopback
// listener for you.
func (t *TunnelImpl[T]) WithListener(l net.Listener) v1.Tunneled {
	if t.listenerSet.CompareAndSwap(false, true) {
		t.provide(l, false)
	} else {
		t.cancel(fmt.Errorf("WithListener: listener already provided"))
	}
	return t
}

// provide adopts l as the local origin and starts the edge connection. The
// caller must have won the listenerSet CAS, so this runs exactly once. minted
// marks a listener the tunnel owns (created by Listener), which is closed when
// the tunnel ends; a caller-provided listener stays caller-owned.
func (t *TunnelImpl[T]) provide(l net.Listener, minted bool) {
	t.Logger().Info("configuring tunnel with local listener", "address", l.Addr().String(), "minted", minted)
	t.listener = l
	close(t.listenerProvided)

	if minted {
		// The tunnel owns a minted listener; close it when the tunnel ends so a
		// canceled tunnel doesn't leak the bound port.
		go func() {
			<-t.ctx.Done()
			l.Close()
		}()
	}

	if t.engine == nil {
		// Foreign backend: the tunnel was born canceled (see New).
		return
	}

	go func() {
		t.Logger().Info("starting tunnel with local listener")
		// Start the DNS readiness poller (it waits on hostnameProvided) and
		// mint the spec, both before the edge connect: the record exists
		// from spec-mint time, so DNS propagation overlaps the (seconds-long)
		// edge dial instead of queuing behind it.
		go t.pollAuthoritative()
		t.Spec()
		if err := t.engine.WithListener(t, l); err != nil {
			t.cancel(fmt.Errorf("backend %q connect: %w", t.engine.Name(), err))
			return
		}

		t.Logger().Info("tunnel connected, waiting for DNS")
		if !await(t.ctx, t.hostnameReady) {
			return
		}

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
	if t.listenerSet.CompareAndSwap(false, true) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.cancel(fmt.Errorf("unable to mint a local listener: %w", err))
			return nil
		}
		t.provide(l, true)
	}
	return t.boundListener()
}

// boundListener blocks until a listener is provided (via WithListener or a
// Listener mint) and returns a tunnel-owned view of it, or nil if the tunnel
// is canceled first. It never mints — the local-side getters use it so
// observing the bind address can't start a tunnel.
func (t *TunnelImpl[T]) boundListener() net.Listener {
	// The listener field is only safe to read once listenerProvided is closed
	// (the close is the happens-before edge for the write), so a cancellation
	// wake returns nil instead of reading the field.
	if !await(t.ctx, t.listenerProvided) {
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

// LocalPort is the listener's bound port. Blocks until a listener is
// provided.
func (t *TunnelImpl[T]) LocalPort() int {
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

// LocalIP is the listener's bound IP. A listener bound to an unspecified
// address (0.0.0.0 / ::) has no concrete IP to report, so it falls back to
// the outbound-route IP, discovered with a UDP dial (no packets are sent).
// Blocks until a listener is provided.
func (t *TunnelImpl[T]) LocalIP() net.IP {
	t.localIPOnce.Do(func() {
		l := t.boundListener()
		if l == nil {
			return
		}

		var ip net.IP
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
		if ip != nil && !ip.IsUnspecified() {
			t.localIP = ip
			return
		}

		t.Logger().Info("listener bound to unspecified address, determining outbound-route IP")
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

// LocalURL is http://<LocalIP>:<LocalPort>/ — the local bind address. It is
// always http: the origin's scheme is a backend setting (WithTLS), not derived
// here, and the public URL carries the real scheme. Blocks until a listener is
// provided.
func (t *TunnelImpl[T]) LocalURL() *url.URL {
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
func (t *TunnelImpl[T]) URL() *url.URL {
	hostname := t.Hostname()

	if p := t.userCtx.Load(); p != nil {
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
		case <-(*p).Done():
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
// resolves publicly.
func (t *TunnelImpl[T]) TunnelReady() <-chan struct{} {
	return t.tunnelReady
}

// fibonacciBackoff is the wait between authoritative poll rounds, in seconds.
// It tracks the observed ~5s window for a fresh quick-tunnel record to land on
// the zone's nameservers and caps at 21s; spot-tests showed the record absent
// at 1–3s, reliably present by 5s. After the sequence is exhausted the poll
// holds at the 21s cap and keeps going until the record appears or tunnel cancel.
var fibonacciBackoff = []time.Duration{1, 1, 2, 3, 5, 8, 13, 21}

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

// pollAuthoritative waits for the spec to provide the public hostname, then
// probes the nameservers each round and fires as soon as one serves the record.
// Rounds ramp through fibonacciBackoff and then hold at its cap; it runs until
// the record appears or the tunnel is canceled.
func (t *TunnelImpl[T]) pollAuthoritative() {
	if !await(t.ctx, t.hostnameProvided) {
		return
	}
	host := dnsName(t.Hostname())
	for round := 0; ; round++ {
		if rec, ok := authoritativeProbe(t.ctx, t.Logger(), t.Domain(), host); ok {
			t.markHostnameReady(host, rec)
			return
		}
		wait := fibonacciBackoff[len(fibonacciBackoff)-1]
		if round < len(fibonacciBackoff) {
			wait = fibonacciBackoff[round]
		}
		t.Logger().Debug("authoritative rung not resolved yet, backing off",
			"hostname", host, "round", round+1, "nextWait", wait*time.Second)
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(wait * time.Second):
		}
	}
}

// authoritativeProbe runs one readiness probe for host in zone domain: it
// returns records and true as soon as one authoritative nameserver serves a
// non-empty A+AAAA set. It is a package var so tests can drive readiness
// deterministically without live DNS; production uses realAuthoritativeProbe.
var authoritativeProbe = realAuthoritativeProbe

// realAuthoritativeProbe queries the zone's nameservers for host's A+AAAA and
// returns the first non-empty answer — one authoritative nameserver serving the
// record is enough, no cross-server agreement required. Nameservers are
// re-resolved each round so a changed delegation is picked up; a server that
// errors, times out, or has no record yet is skipped, and a round with no
// non-empty answer keeps polling.
func realAuthoritativeProbe(ctx context.Context, log *slog.Logger, domain, host string) (resolver.Records, bool) {
	servers := nameserverIPs(ctx, log, domain)
	if len(servers) == 0 {
		log.Debug("no authoritative nameservers discovered yet", "domain", domain)
		return resolver.Records{}, false
	}

	for _, server := range servers {
		qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		rec, err := resolver.Query(qctx, server, host)
		cancel()
		log.Debug("authoritative query", "hostname", host, "server", server, "A", rec.A, "AAAA", rec.AAAA, "error", err)
		if err != nil || rec.Empty() {
			continue
		}
		return rec, true
	}
	return resolver.Records{}, false
}

// nameserverIPs resolves the zone's NS records to IPv4 ip:53 endpoints via the
// system resolver. NS records are stable and are not the propagation target, so
// the system resolver is fine here — the record we wait on is queried at these
// servers directly. The bare zone name is used (DNS queries take no :port,
// which the v1 contract allows GetHostname to carry).
//
// Only IPv4 endpoints are kept: an IPv6 NS anycast address on an IPv4-only host
// (e.g. a GitHub Actions runner) yields "connect: no route to host", burning a
// 5s query timeout each round for nothing. Every Cloudflare NS has an IPv4
// anycast address, so v4-only loses no nameserver.
func nameserverIPs(ctx context.Context, log *slog.Logger, domain string) []string {
	ns, err := net.DefaultResolver.LookupNS(ctx, dnsName(domain))
	if err != nil {
		log.Debug("authoritative NS lookup failed", "domain", domain, "error", err)
		return nil
	}
	var servers []string
	for _, record := range ns {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", record.Host)
		if err != nil {
			log.Debug("nameserver address lookup failed", "nameserver", record.Host, "error", err)
			continue
		}
		for _, ip := range ips {
			servers = append(servers, net.JoinHostPort(ip.String(), "53"))
		}
	}
	return servers
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
