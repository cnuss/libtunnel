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
)

// WithLogger sets the logger. A no-op once a listener has been provided.
func (t *TunnelImpl[T]) WithLogger(log *slog.Logger) v1.Tunnel[T] {
	select {
	case <-t.listenerProvided:
	default:
		if log != nil {
			t.log.Store(log)
		}
	}
	return t
}

// WithListener provides the local listener and lazily starts the edge
// connection. The listener is the single source of local-side truth: LocalIP,
// LocalPort, and LocalURL all derive from its address. The returned
// v1.Connected carries no mutators — there is nothing left to configure.
func (t *TunnelImpl[T]) WithListener(l net.Listener) v1.Connected[T] {
	t.listenerOnce.Do(func() {
		t.Logger().Info("configuring tunnel with local listener", "address", l.Addr().String())
		t.listener = l
		close(t.listenerProvided)

		engine, ok := t.backend.(Engine[T])
		if !ok {
			t.cancel(fmt.Errorf("backend %q does not implement the v1alpha1 engine contract", t.backend.Name()))
			return
		}

		go func() {
			t.Logger().Info("starting tunnel with local listener")
			if err := engine.WithListener(t, l); err != nil {
				t.cancel(fmt.Errorf("backend %q connect: %w", engine.Name(), err))
				return
			}

			t.Logger().Info("tunnel connected, waiting for DNS")
			select {
			case <-t.ctx.Done():
				return
			case <-t.HostnameReady():
			}

			t.Logger().Info("tunnel is ready")
			close(t.tunnelReady)
		}()
	})
	return t
}

// Listener returns a tunnel-owned view of the provided listener, blocking
// until WithListener is called or the tunnel context is canceled (then nil).
// Closing the returned listener closes the tunnel; the original listener
// stays caller-owned, so closing that restarts the origin while the tunnel
// persists.
func (t *TunnelImpl[T]) Listener() net.Listener {
	select {
	case <-t.listenerProvided:
	case <-t.ctx.Done():
		// The listener field is only safe to read once listenerProvided is
		// closed (the close is the happens-before edge for the write), so a
		// cancellation wake re-checks instead of reading the field.
		select {
		case <-t.listenerProvided:
		default:
			return nil
		}
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
// zone's authoritative nameservers. Returns nil if the tunnel is canceled
// before that happens, per the v1 contract's zero-value-on-cancel rule.
func (t *TunnelImpl[T]) URL() *url.URL {
	t.urlOnce.Do(func() {
		hostname := t.Hostname()
		select {
		case <-t.ctx.Done():
		case <-t.HostnameReady():
		}
		// Build only if the hostname actually resolved — a cancellation wake
		// leaves the zero value. Re-checking (rather than branching on which
		// case fired) also covers both channels being ready at once.
		select {
		case <-t.HostnameReady():
			t.url = &url.URL{
				Scheme: "https",
				Host:   hostname,
				Path:   "/",
			}
		default:
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
		t.Logger().Info("loaded CA certificates for tunnel", "numCACerts", len(t.caCerts))
	})
	return t.caCerts
}

// TunnelReady is closed when the edge connection is up and the hostname
// resolves publicly.
func (t *TunnelImpl[T]) TunnelReady() <-chan struct{} {
	return t.tunnelReady
}

// HostnameReady starts (on first use) a poller that watches the zone's
// authoritative nameservers and closes the returned channel once the tunnel
// hostname resolves there. Polling the authoritative servers directly avoids
// waiting out negative-cache TTLs on recursive resolvers and reflects
// provisioning truth: the record exists the moment the zone serves it.
func (t *TunnelImpl[T]) HostnameReady() <-chan struct{} {
	t.hostnameReadyOnce.Do(func() {
		// authServers resolves the zone's authoritative nameservers to ip:53
		// endpoints. Run once up front and stashed; NS records are stable.
		// DNS queries take bare names, so any :port the spec's hostname
		// carries (the v1 contract allows host:port) is stripped first.
		authServers := func() []string {
			ns, err := net.DefaultResolver.LookupNS(t.ctx, dnsName(t.Domain()))
			if err != nil {
				return nil
			}

			ips := make([]string, 0, len(ns))
			for _, record := range ns {
				hostIPs, err := net.DefaultResolver.LookupHost(t.ctx, record.Host)
				if err != nil {
					continue
				}
				for _, ip := range hostIPs {
					ips = append(ips, net.JoinHostPort(ip, "53"))
				}
			}
			return ips
		}

		go func() {
			// Discover the authoritative servers once, retrying until available.
			var ips []string
			for {
				if ips = authServers(); len(ips) > 0 {
					break
				}
				t.Logger().Debug("no authoritative nameservers discovered yet, retrying", "domain", t.Domain())
				select {
				case <-t.ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
			t.Logger().Debug("discovered authoritative nameservers", "domain", t.Domain(), "servers", ips)

			d := net.Dialer{Timeout: 5 * time.Second}
			// target is the authoritative server the next query goes to —
			// re-picked per attempt (randomized so one bad server can't wedge
			// the poll) and captured here so the logs can name it.
			var target string
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return d.DialContext(ctx, network, target)
				},
			}

			host := dnsName(t.Hostname())
			for attempt := 1; ; attempt++ {
				target = ips[time.Now().UnixNano()%int64(len(ips))]
				t.Logger().Debug("querying authoritative nameserver", "hostname", host, "server", target, "attempt", attempt)

				started := time.Now()
				ctx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
				addrs, err := r.LookupHost(ctx, host)
				cancel()
				t.Logger().Debug("authoritative query answered", "hostname", host, "server", target, "attempt", attempt, "took", time.Since(started), "addrs", addrs, "error", err)

				if err == nil && len(addrs) > 0 {
					t.Logger().Info("hostname resolved on authoritative nameservers", "hostname", host, "addrs", addrs, "attempts", attempt)
					close(t.hostnameReady)
					return
				}

				select {
				case <-t.ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}
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
