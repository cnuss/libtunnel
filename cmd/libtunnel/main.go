// Command libtunnel is the env-only tunnel launcher: a standalone binary with
// no flags and no config files — every knob comes from the environment, the
// same variables the library reads (see package v1). It is the operator-side
// face of libtunnel's twelve-factor design, shaped for `docker run -e ...`.
//
// Activation. A backend must be selected:
//
//   - LIBTUNNEL_SPEC set (a spec handoff already names its backend), or
//   - LIBTUNNEL__CLOUDFLARE=1 (the explicit Cloudflare switch).
//
// Origin. A standalone binary has no listener to inherit, so the origin is a
// URL: LIBTUNNEL_LOCAL_URL points at the already-running local service (e.g.
// http://localhost:8080), the `cloudflared tunnel --url` shape. It is
// required — unset is a fatal error, not a dead loopback mint.
//
// Everything else — LIBTUNNEL_TLS / LIBTUNNEL_HTTP2, LIBTUNNEL_FROM, the
// LIBTUNNEL__CLOUDFLARE_* spec fields, LIBTUNNEL_LOG — flows through the
// library's own env mirrors with no plumbing here. On success the public URL
// is printed to stdout (one line, machine-consumable; logs go to stderr via
// LIBTUNNEL_LOG); the process then runs until SIGINT/SIGTERM, or exits
// non-zero if the tunnel fails first. Minting also exports LIBTUNNEL_SPEC and
// LIBTUNNEL_HOSTNAME into the environment, so any child this process spawns
// inherits the same tunnel identity.
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/cnuss/libtunnel"
	v1 "github.com/cnuss/libtunnel/v1"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "libtunnel: "+err.Error())
		os.Exit(1)
	}
}

// run builds the tunnel from the environment, prints its public URL to
// stdout, and blocks until ctx is canceled (a signal) or the tunnel fails. It
// takes ctx and stdout as parameters so the offline failure modes are
// testable without a real mint.
func run(ctx context.Context, stdout io.Writer) error {
	tun, err := build(ctx)
	if err != nil {
		return err
	}

	// WithContext (set in build) makes URL wait for end-to-end readiness and
	// return nil on ctx cancel or tunnel failure — so a signal during startup
	// exits cleanly instead of hanging.
	url := tun.URL()
	if url == nil {
		return cmp.Or(tun.Err(), ctx.Err(), errors.New("tunnel did not become ready"))
	}
	fmt.Fprintln(stdout, url)

	select {
	case <-ctx.Done():
		return nil // signaled after the tunnel came up: clean shutdown
	case <-tun.Done():
		return tun.Err()
	}
}

// build validates the environment and returns the configured, unstarted
// tunnel. The two failure modes — no backend activated, no origin — are
// checked here so they surface as clean errors before any network use.
func build(ctx context.Context) (libtunnel.TunnelV1, error) {
	if !cloudflareActivated() {
		return nil, fmt.Errorf("no backend activated: set %s (a spec handoff) or %s=1", v1.SpecEnv, v1.CloudflareEnv)
	}
	// The library would otherwise mint a dead loopback listener nothing serves
	// on; a standalone binary needs a real origin URL.
	if os.Getenv(v1.LocalURLEnv) == "" {
		return nil, fmt.Errorf("no origin: set %s to the local service URL (e.g. http://localhost:8080)", v1.LocalURLEnv)
	}
	return libtunnel.New(libtunnel.Cloudflare()).WithContext(ctx), nil
}

// cloudflareActivated reports whether the environment selects the Cloudflare
// backend: an inherited spec handoff, or the explicit switch.
func cloudflareActivated() bool {
	return os.Getenv(v1.SpecEnv) != "" || os.Getenv(v1.CloudflareEnv) == "1"
}
