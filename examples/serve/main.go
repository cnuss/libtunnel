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
	"net"
	"net/http"
	"os"

	"github.com/cnuss/libtunnel"
)

func main() {
	// You own the bind. The tunnel infers everything else from the listener —
	// including whether the origin speaks TLS (wrap with tls.NewListener and
	// the ingress switches to https automatically).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}

	// Unset, the tunnel is silent. Error keeps the output quiet; Info would
	// show the tunnel lifecycle, Debug adds cloudflared's internals.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	conn := libtunnel.New(libtunnel.Cloudflare()).
		WithLogger(logger).
		WithListener(l)

	go func() {
		err := http.Serve(conn.Listener(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello from libtunnel")
		}))
		log.Fatal(err)
	}()

	fmt.Printf("local: %s\n", conn.LocalURL())

	// HostnameReady fires once the hostname resolves on the zone's
	// authoritative nameservers; TunnelReady once the edge connection is up
	// too — the tunnel is then reachable end to end.
	<-conn.HostnameReady()
	fmt.Printf("hostname: %s\n", conn.Hostname())

	<-conn.TunnelReady()
	fmt.Printf("✓ tunneled %s to %s\n", conn.LocalURL(), conn.URL())

	resp, err := http.Get(conn.URL().String())
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("served: %s\n", body)
}
