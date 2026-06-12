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

// LocalURL is https://<LocalIP>:<LocalPort>/. Blocks until a listener is
// provided.
func (t *TunnelImpl[T]) LocalURL() *url.URL {
	t.localURLOnce.Do(func() {
		ip := t.LocalIP()
		if ip == nil {
			return
		}
		t.localURL = &url.URL{
			Scheme: "https",
			Host:   net.JoinHostPort(ip.String(), strconv.Itoa(t.LocalPort())),
			Path:   "/",
		}
	})
	return t.localURL
}

// Spec returns the resolved tunnel spec, fetching it from the configured
// provider (or the backend's default chain) on first use.
func (t *TunnelImpl[T]) Spec() T {
	t.specOnce.Do(func() {
		if t.provider == nil {
			t.cancel(fmt.Errorf("no provider configured"))
			return
		}

		t.log.Info("fetching tunnel spec")
		spec, err := t.provider.Spec(t.ctx)
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

// HostnameReady starts (on first use) a poller that watches the zone's
// authoritative nameservers and closes the returned channel once the tunnel
// hostname resolves there. Polling the authoritative servers directly avoids
// waiting out negative-cache TTLs on local resolvers.
func (t *TunnelImpl[T]) HostnameReady() <-chan struct{} {
	t.hostnameReadyOnce.Do(func() {
		// authServers resolves the zone's authoritative nameservers to ip:53
		// endpoints. Run once up front and stashed; NS records are stable.
		authServers := func() []string {
			ns, err := net.DefaultResolver.LookupNS(t.ctx, t.Domain())
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
				select {
				case <-t.ctx.Done():
					return
				case <-time.After(time.Second):
				}
			}

			d := net.Dialer{Timeout: 5 * time.Second}
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					// randomize across all authoritative servers instead of always picking the first one
					return d.DialContext(ctx, network, ips[time.Now().UnixNano()%int64(len(ips))])
				},
			}

			for {
				ctx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
				addrs, err := r.LookupHost(ctx, t.Hostname())
				cancel()

				if err == nil && len(addrs) > 0 {
					t.log.Info("hostname resolved on authoritative nameservers", "hostname", t.Hostname(), "addrs", addrs)
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
