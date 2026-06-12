package v1alpha1

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
)

// WithLogger sets the logger. A no-op once a listener has been provided.
func (t *TunnelImpl[T]) WithLogger(log *slog.Logger) v1.Tunnel[T] {
	select {
	case <-t.listenerProvided:
	default:
		t.log = log
	}
	return t
}

// WithListener provides the local listener and lazily starts the edge
// connection. The listener is the single source of local-side truth: LocalIP,
// LocalPort, and LocalURL all derive from its address. The returned
// v1.Connected carries no mutators — there is nothing left to configure.
func (t *TunnelImpl[T]) WithListener(l net.Listener) v1.Connected[T] {
	t.listenerOnce.Do(func() {
		t.log.Info("configuring tunnel with local listener", "address", l.Addr().String())
		t.listener = l
		close(t.listenerProvided)

		engine, ok := t.backend.(Engine[T])
		if !ok {
			t.cancel(fmt.Errorf("backend %q does not implement the v1alpha1 engine contract", t.backend.Name()))
			return
		}

		go func() {
			t.log.Info("starting tunnel with local listener")
			if err := engine.WithListener(t, l); err != nil {
				t.cancel(fmt.Errorf("backend %q connect: %w", engine.Name(), err))
				return
			}

			t.log.Info("tunnel connected, waiting for DNS")
			select {
			case <-t.ctx.Done():
				return
			case <-t.HostnameReady():
			}

			t.log.Info("tunnel is ready")
			close(t.tunnelReady)
		}()
	})
	return t
}

// Listener returns the provided listener, blocking until WithListener is
// called or the tunnel context is canceled (then nil).
func (t *TunnelImpl[T]) Listener() net.Listener {
	<-await(t.ctx, t.listenerProvided)
	return t.listener
}

// LocalPort is the listener's bound port. Blocks until a listener is
// provided.
func (t *TunnelImpl[T]) LocalPort() int {
	l := t.Listener()
	if l == nil {
		return 0
	}
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
		l := t.Listener()
		if l == nil {
			return
		}

		host, _, err := net.SplitHostPort(l.Addr().String())
		if err != nil {
			t.cancel(fmt.Errorf("unable to determine local IP from listener address %q: %w", l.Addr(), err))
			return
		}

		if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
			t.localIP = ip
			return
		}

		t.log.Info("listener bound to unspecified address, determining outbound-route IP")
		conn, err := net.Dial("udp", "1.1.1.1:53")
		if err != nil {
			t.cancel(fmt.Errorf("unable to get local IP: %w", err))
			return
		}
		defer conn.Close()
		t.localIP = conn.LocalAddr().(*net.UDPAddr).IP
		t.log.Info("determined local IP for tunnel", "localIP", t.localIP.String())
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

// LocalURL is <scheme>://<LocalIP>:<LocalPort>/, where the scheme follows the
// listener (https when it terminates TLS, http otherwise). Blocks until a
// listener is provided.
func (t *TunnelImpl[T]) LocalURL() *url.URL {
	t.localURLOnce.Do(func() {
		ip := t.LocalIP()
		if ip == nil {
			return
		}
		scheme := "http"
		if IsTLS(t.listener) {
			scheme = "https"
		}
		t.localURL = &url.URL{
			Scheme: scheme,
			Host:   net.JoinHostPort(ip.String(), strconv.Itoa(t.LocalPort())),
			Path:   "/",
		}
	})
	return t.localURL
}

// Spec returns the resolved tunnel spec, fetching it from the backend's
// provider chain on first use.
func (t *TunnelImpl[T]) Spec() T {
	t.specOnce.Do(func() {
		provider := t.backend.Provider()
		// Providers that can log (retry warnings, rate limits) pick up the
		// tunnel's logger here — they're built by the backend before any
		// WithLogger call, so the logger is threaded late.
		if pl, ok := provider.(interface{ SetLogger(*slog.Logger) }); ok {
			pl.SetLogger(t.log)
		}

		t.log.Info("fetching tunnel spec")
		spec, err := provider.Spec(t.ctx)
		if err != nil {
			t.cancel(fmt.Errorf("unable to fetch tunnel spec: %w", err))
			return
		}
		t.spec = spec
		t.log.Info("fetched tunnel spec", "hostname", spec.GetHostname())
	})
	return t.spec
}

// Hostname is the public hostname from the spec.
func (t *TunnelImpl[T]) Hostname() string {
	t.hostnameOnce.Do(func() {
		t.hostname = t.Spec().GetHostname()
	})
	return t.hostname
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
// zone's authoritative nameservers.
func (t *TunnelImpl[T]) URL() *url.URL {
	t.urlOnce.Do(func() {
		hostname := t.Hostname()
		<-await(t.ctx, t.HostnameReady())
		t.url = &url.URL{
			Scheme: "https",
			Host:   hostname,
			Path:   "/",
		}
	})
	return t.url
}

// CACerts returns the backend's trust roots for its edge connections.
func (t *TunnelImpl[T]) CACerts() []*x509.Certificate {
	t.caCertsOnce.Do(func() {
		engine, ok := t.backend.(Engine[T])
		if !ok {
			t.cancel(fmt.Errorf("backend %q does not implement the v1alpha1 engine contract", t.backend.Name()))
			return
		}
		t.caCerts = engine.CACerts()
		t.log.Info("loaded CA certificates for tunnel", "numCACerts", len(t.caCerts))
	})
	return t.caCerts
}

// TunnelReady is closed when the edge connection is up and the hostname
// resolves publicly.
func (t *TunnelImpl[T]) TunnelReady() <-chan struct{} {
	return t.tunnelReady
}

// publicResolvers are well-known anycast recursive resolvers. The
// HostnameReady poller consumes one per attempt and never returns to it, so
// a resolver that has already cached a negative answer for the hostname is
// left behind instead of wedging the wait. Public recursives also work on
// networks that intercept DNS or block direct authoritative queries.
var publicResolvers = []string{
	"1.1.1.1:53",         // Cloudflare
	"8.8.8.8:53",         // Google
	"9.9.9.9:53",         // Quad9
	"208.67.222.222:53",  // OpenDNS
	"1.0.0.1:53",         // Cloudflare secondary
	"8.8.4.4:53",         // Google secondary
	"149.112.112.112:53", // Quad9 secondary
	"208.67.220.220:53",  // OpenDNS secondary
	"94.140.14.14:53",    // AdGuard
	"76.76.2.0:53",       // Control D
}

// HostnameReady starts (on first use) a poller that walks a fleet of public
// resolvers — one query per resolver, sleeping a second between attempts —
// and closes the returned channel once the tunnel hostname resolves. When
// the fleet is exhausted without an answer, the tunnel is canceled with a
// descriptive cause: the hostname is considered never coming.
func (t *TunnelImpl[T]) HostnameReady() <-chan struct{} {
	t.hostnameReadyOnce.Do(func() {
		go func() {
			remaining := slices.Clone(publicResolvers)

			d := net.Dialer{Timeout: 5 * time.Second}
			// target is the resolver the next query goes to — captured so
			// the custom Dial and the logs name the same server.
			var target string
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return d.DialContext(ctx, network, target)
				},
			}

			for attempt := 1; len(remaining) > 0; attempt++ {
				target, remaining = remaining[0], remaining[1:]
				t.log.Debug("querying public resolver", "hostname", t.Hostname(), "server", target, "attempt", attempt)

				started := time.Now()
				ctx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
				addrs, err := r.LookupHost(ctx, t.Hostname())
				cancel()
				t.log.Debug("public resolver answered", "hostname", t.Hostname(), "server", target, "attempt", attempt, "took", time.Since(started), "addrs", addrs, "error", err)

				if err == nil && len(addrs) > 0 {
					t.log.Info("hostname resolved", "hostname", t.Hostname(), "addrs", addrs, "resolver", target, "attempts", attempt)
					close(t.hostnameReady)
					return
				}

				select {
				case <-t.ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}

			t.cancel(fmt.Errorf("hostname %q did not resolve on any of %d public resolvers", t.Hostname(), len(publicResolvers)))
		}()
	})
	return t.hostnameReady
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

// IsTLS reports whether l terminates TLS itself, so origin URLs can carry the
// matching scheme. crypto/tls's listener type is unexported, so detection
// probes an opt-in interface first (custom listeners can declare themselves
// with a `TLS() bool` method) and falls back to the concrete type name for
// listeners straight out of tls.Listen/tls.NewListener.
func IsTLS(l net.Listener) bool {
	if t, ok := l.(interface{ TLS() bool }); ok {
		return t.TLS()
	}
	return fmt.Sprintf("%T", l) == "*tls.listener"
}

// await bridges a receive on ch with cancellation: the returned channel
// closes when ch yields or ctx is done, whichever comes first.
func await[E any](ctx context.Context, ch <-chan E) <-chan struct{} {
	out := make(chan struct{})
	go func() {
		defer close(out)
		select {
		case <-ctx.Done():
		case <-ch:
		}
	}()
	return out
}
