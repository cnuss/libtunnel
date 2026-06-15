// Command serve exposes a local HTTP server to the public internet through a
// Cloudflare quick tunnel, waits until the tunnel is reachable end to end,
// then requests its own public URL to prove the round trip.
//
// It needs network access (it mints a tunnel from api.trycloudflare.com); the
// e2e harness only runs it when LIBTUNNEL_E2E_LIVE=1.
package main

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
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

	// You own the bind. The tunnel infers everything else from the listener —
	// including whether the origin speaks TLS (wrap with tls.NewListener and
	// the ingress switches to https automatically).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}

	// Unset, the tunnel is silent. Info shows the tunnel lifecycle (including
	// rate-limit retry warnings); Debug adds cloudflared's internals and the
	// DNS-readiness probe detail. Set LIBTUNNEL_LOG_LEVEL=debug to raise it.
	level := slog.LevelInfo
	if os.Getenv("LIBTUNNEL_LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	// WithContext upgrades URL from "the hostname resolves" to "the tunnel is
	// reachable end to end": URL then blocks until TunnelReady, honoring ctx.
	tun := libtunnel.New(libtunnel.Cloudflare()).
		WithLogger(logger).
		WithContext(ctx).
		WithListener(l)

	go func() {
		err := http.Serve(tun.Listener(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello from libtunnel")
		}))
		log.Fatal(err)
	}()

	fmt.Printf("local: %s\n", tun.LocalURL())

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

// fetch GETs url, retrying until it answers 200 or ctx is done.
func fetch(ctx context.Context, url string) (string, error) {
	var lastErr error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		resp, err := http.DefaultClient.Do(req)
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
