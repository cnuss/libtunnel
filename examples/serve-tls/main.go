// Command serve-tls is serve's TLS twin: it hands WithListener a TLS listener
// (tls.Listen over a self-signed, in-process cert) instead of a plain one, so
// the tunnel dials the origin over https. The ingress scheme follows the
// listener — a TLS listener flips the origin to https automatically, and the
// engine dials it with verification off, so a self-signed cert is fine.
//
// The public fetch still hits the Cloudflare edge, which presents a valid
// certificate, so the client needs no InsecureSkipVerify: the self-signed
// cert lives only between the in-process connector and the local origin.
//
// It needs network access (it mints a tunnel from api.trycloudflare.com); the
// e2e harness only runs it when LIBTUNNEL_E2E_LIVE=1.
package main

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cnuss/libtunnel"
)

func main() {
	// One context governs everything below: tunnel readiness (via WithContext)
	// and the proof-of-round-trip fetch share this single deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// You own the bind. tls.Listen wraps a TCP listener with the cert below;
	// the tunnel infers https from it (try plain net.Listen and the ingress
	// falls back to http). Accept() yields *tls.Conn.
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned()},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Unset, the tunnel is silent. Info shows the tunnel lifecycle (including
	// rate-limit retry warnings); Debug adds cloudflared's internals.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// WithContext upgrades URL from "the hostname resolves" to "the tunnel is
	// reachable end to end": URL then blocks until TunnelReady, honoring ctx.
	tun := libtunnel.New(libtunnel.Cloudflare()).
		WithLogger(logger).
		WithContext(ctx).
		WithListener(l)

	go func() {
		err := http.Serve(tun.Listener(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello from libtunnel (tls)")
		}))
		log.Fatal(err)
	}()

	fmt.Printf("local: %s\n", tun.LocalURL()) // https://127.0.0.1:<port>/ — the TLS origin

	// URL returns nil if the tunnel failed or the deadline elapsed first —
	// Err() reports a tunnel failure, ctx.Err() a timeout.
	url := tun.URL()
	if url == nil {
		log.Fatal(cmp.Or(tun.Err(), ctx.Err()))
	}
	fmt.Printf("✓ tunneled %s to %s\n", tun.LocalURL(), url)

	// The first request can race propagation: TunnelReady proves the
	// authoritative nameservers serve the record, but this machine's own
	// resolver and the edge route may lag a few seconds behind. Retry — the
	// same ctx bounds the wait, so it shares the deadline with readiness above.
	body, err := fetch(ctx, url.String())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("served: %s\n", body)
}

// selfSigned mints a throwaway ECDSA certificate for 127.0.0.1, in memory. The
// origin connector dials with verification off, so it never needs to be a real
// CA-issued cert — this is the minimum a TLS listener requires.
func selfSigned() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "libtunnel serve-tls example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fetch GETs url, retrying until it answers 200 or ctx is done.
func fetch(ctx context.Context, url string) (string, error) {
	var lastErr error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		resp, err := libtunnel.HTTPClient().Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil && resp.StatusCode == http.StatusOK {
				return string(body), nil
			}
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
		}

		select {
		case <-ctx.Done():
			return "", fmt.Errorf("%s never answered: %w", url, cmp.Or(lastErr, ctx.Err()))
		case <-time.After(2 * time.Second):
		}
	}
}
