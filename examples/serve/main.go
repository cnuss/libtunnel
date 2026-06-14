// Command serve exposes a local HTTP server to the public internet through a
// Cloudflare quick tunnel, waits until the tunnel is reachable end to end,
// then requests its own public URL to prove the round trip.
//
// It needs network access (it mints a tunnel from api.trycloudflare.com); the
// e2e harness only runs it when LIBTUNNEL_E2E_LIVE=1.
package main

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/cnuss/libtunnel"
)

func main() {
	// Unset, the tunnel is silent. Info shows the tunnel lifecycle (including
	// rate-limit retry warnings); Debug adds cloudflared's internals.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// No WithListener: the first call that needs a local origin auto-provisions
	// a loopback listener on 127.0.0.1:0 and starts the edge connection. Bring
	// your own with WithListener when you need a specific bind or TLS origin
	// (wrap it with tls.NewListener and the ingress switches to https).
	tun := libtunnel.New(libtunnel.Cloudflare()).WithLogger(logger)

	go func() {
		err := http.Serve(tun.Listener(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello from libtunnel")
		}))
		log.Fatal(err)
	}()

	fmt.Printf("local: %s\n", tun.LocalURL())

	// TunnelReady fires when the edge connection is up and the hostname
	// resolves publicly; Done fires if the tunnel fails instead — always
	// select on both, or a failed tunnel blocks forever.
	select {
	case <-tun.TunnelReady():
	case <-tun.Done():
		log.Fatal(tun.Err())
	}
	fmt.Printf("✓ tunneled %s to %s\n", tun.LocalURL(), tun.URL())

	// The first request can race propagation: TunnelReady proves the
	// authoritative nameservers serve the record, but this machine's own
	// resolver and the edge route may lag a few seconds behind. Retry briefly
	// — real clients hitting a fresh tunnel face the same window.
	body, err := fetch(tun.URL().String())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("served: %s\n", body)
}

// fetch GETs url, retrying for up to 30 seconds until it answers 200.
func fetch(url string) (string, error) {
	var lastErr error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		resp, err := http.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil && resp.StatusCode == http.StatusOK {
			return string(body), nil
		}
		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	return "", fmt.Errorf("%s never answered: %w", url, lastErr)
}
