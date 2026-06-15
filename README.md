# libtunnel

[![Go Reference](https://pkg.go.dev/badge/github.com/cnuss/libtunnel.svg)](https://pkg.go.dev/github.com/cnuss/libtunnel)
[![Go Report Card](https://goreportcard.com/badge/github.com/cnuss/libtunnel)](https://goreportcard.com/report/github.com/cnuss/libtunnel)
[![CI](https://github.com/cnuss/libtunnel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cnuss/libtunnel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/cnuss/libtunnel/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/cnuss/libtunnel/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cnuss/libtunnel/badge)](https://scorecard.dev/viewer/?uri=github.com/cnuss/libtunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

`libtunnel` exposes a local `net.Listener` to the public internet through a
tunnel backend — Cloudflare quick tunnels first, driven entirely in-process
(no `cloudflared` binary required).

The API is pure-lazy: every getter resolves on first use, and `WithListener`
is the trigger that starts the edge connection. Once it fires, the returned
value narrows to a `Tunneled` running handle — the mutators and the pre-start
introspection (spec getters, `HostnameReady`) are gone, leaving how to reach
the tunnel and how to watch it, and the type system says so.

## Quick Start

```sh
go get github.com/cnuss/libtunnel
```

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/cnuss/libtunnel"
)

func main() {
	l, _ := net.Listen("tcp", "127.0.0.1:0") // you own the bind

	conn := libtunnel.New(libtunnel.Cloudflare()).
		WithContext(context.Background()). // URL waits for end-to-end readiness
		WithListener(l)                    // lazily starts the edge connection

	go http.Serve(conn.Listener(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from libtunnel")
	}))

	url := conn.URL() // blocks until reachable end to end (see WithContext)
	if url == nil {
		log.Fatal(conn.Err())
	}
	fmt.Println(url) // https://<something>.trycloudflare.com/
}
```

(The ingress scheme follows the listener: hand over a plain listener and the
origin is dialed over http; wrap it with `tls.NewListener` — or implement
`TLS() bool` on a custom listener — and the ingress switches to https,
self-signed certificates welcome.)

## Layout

Three packages, stable/alpha versioning:

```
github.com/cnuss/libtunnel                      — root façade: New, backends,
                                                  providers, handoff helpers.
github.com/cnuss/libtunnel/v1                   — stable Tunnel/Tunneled +
                                                  Provider[T]/Backend[T] contract.
github.com/cnuss/libtunnel/v1alpha1             — lazy tunnel core + generic
                                                  providers. May change between
                                                  alpha revisions.
github.com/cnuss/libtunnel/v1alpha1/cloudflare  — the cloudflared quick-tunnel
                                                  engine + its Spec type.
```

Application code imports the root (`libtunnel.New(...)`). Code that needs to
declare types against the interfaces imports `v1`. Direct access to the
implementation lives in `v1alpha1`.

For the file-by-file map, see
[CONTRIBUTING.md → Where to find things](./CONTRIBUTING.md#where-to-find-things).

## API at a glance

```go
// configurable phase — mutators chain until WithListener narrows the type.
// Non-generic: the spec type is a construction-time detail, so a tunnel
// reference stores without threading T through caller code.
type Tunnel interface {
    Tunneled

    LocalIP() net.IP // local side, inferred from the listener
    LocalHost() string

    Host() string // public side, derived from the spec
    Hostname() string
    Domain() string
    Port() int
    CACerts() []*x509.Certificate
    HostnameReady() <-chan struct{} // hostname resolves on authoritative NS

    WithLogger(log *slog.Logger) Tunnel      // default: silent
    WithContext(ctx context.Context) Tunnel  // URL waits end-to-end, honors ctx
    WithListener(l net.Listener) Tunneled   // starts the connection
}

// post-WithListener phase — the running handle: reach it, watch it
type Tunneled interface {
    LocalPort() int
    LocalURL() *url.URL
    Listener() net.Listener

    URL() *url.URL // blocks until the hostname resolves (end-to-end w/ WithContext)

    TunnelReady() <-chan struct{}   // connection up + hostname resolves
    Done() <-chan struct{}          // tunnel failed or shut down
    Err() error                     // why (nil while alive)
}

type Provider[T Spec] interface { Spec(ctx context.Context) (T, error) }
type Backend[T Spec] interface { // opaque; the engine contract is alpha-internal
    Name() string
    Provider() Provider[T] // the backend's credential chain
}
type Spec interface { GetHostname() string }

// façade
func New[T v1.Spec](backend v1.Backend[T]) v1.Tunnel // T wires the backend, not the result
func Cloudflare() v1.Backend[*cloudflare.Spec]   // in-process cloudflared engine;
                                                 // adopts TUNNEL_SPEC, else mints
                                                 // an anonymous quick tunnel

// parent→child handoff — no API: minting exports the TUNNEL_SPEC env var,
// construction adopts it
```

## Parent→child handoff

`TUNNEL_SPEC` is a first-class handoff channel with nothing to call: when
the Cloudflare credential chain mints a spec it exports it into the
process's environment, and at construction it adopts one found there. A
spawned child (or a re-exec) therefore connects under the same hostname —
no second quick-tunnel resolution, no plumbing.

Two guardrails keep the channel safe: a process never re-adopts a spec it
exported itself (a second tunnel in the same process mints its own identity
instead of inheriting the first one's), and the exported value is tagged
with the backend that minted it, so a child running a different backend
fails loudly instead of silently unmarshaling a foreign spec.

```go
// parent: forcing the mint exports TUNNEL_SPEC as a side effect (never
// connects itself); Hostname triggers the mint and returns the public name
libtunnel.New(libtunnel.Cloudflare()).Hostname()
cmd := exec.Command(os.Args[0], "child") // inherits the environment

// child: the Cloudflare credential chain finds TUNNEL_SPEC and adopts it
conn := libtunnel.New(libtunnel.Cloudflare()).WithListener(l)
```

(Full source: [`examples/subprocess/main.go`](./examples/subprocess/main.go).)

## Examples

Self-contained programs in [`./examples`](./examples):

| Example   | Demonstrates                                                       |
| --------- | ------------------------------------------------------------------ |
| `serve`   | Real quick tunnel: serve locally, request the public URL.           |
| `serve-tls` | Same as `serve`, but a TLS listener (`tls.Listen`) — ingress flips to https. |
| `subprocess` | Parent mints a spec; child adopts it via `TUNNEL_SPEC` and serves. |

Run one locally:

```sh
make run serve
make run serve-tls
make run subprocess
```

## Testing

```sh
make test   # library unit + fuzz tests (fast, in-package)
make e2e    # live tier: real tunnels through the real edge (gated)
```

`make e2e` runs `go test -count=1 -v ./e2e`. The `-count=1` defeats the test
cache, since the harness builds the example binaries at runtime and the cache
key wouldn't otherwise pick up example source changes. The e2e tier is live
tunnels only — everything mints from `api.trycloudflare.com` (rate-limited),
so the whole tier is skipped unless you opt in (offline subprocess handoff
coverage lives in the unit tier and always runs):

```sh
LIBTUNNEL_E2E_LIVE=1 make e2e
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the local dev loop, release
process, and what makes a good example.

## License

[MIT](./LICENSE)
