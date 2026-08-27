// Package e2e is the live tier: real quick tunnels through the real
// Cloudflare edge, skipped under -short (`make test`) and run by `make e2e`.
// It builds and runs the example binaries and adds live scenario tests of
// its own; on CI each platform runs at most one tier (see the tier-selection
// block in util_test.go). Anything that can pass without a real tunnel
// belongs in the unit tier instead.
//
// Run with: go test -count=1 ./e2e
package e2e
