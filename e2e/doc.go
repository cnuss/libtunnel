// Package e2e is the live tier: real quick tunnels through the real
// Cloudflare edge, gated behind LIBTUNNEL_E2E_LIVE=1. It builds and runs the
// example binaries and adds live scenario tests of its own. Anything that
// can pass without a real tunnel belongs in the unit tier instead.
//
// Run with: LIBTUNNEL_E2E_LIVE=1 go test -count=1 ./e2e
package e2e
