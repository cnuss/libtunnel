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
value narrows to a mutator-free `Connected` — there is nothing left to
configure, and the type system says so.

## Quick Start

```sh
go get github.com/cnuss/libtunnel
```

```go
package main

import (
	"fmt"
	"net"
	"net/http"

	"github.com/cnuss/libtunnel"
)

func main() {
	l, _ := net.Listen("tcp", "127.0.0.1:0") // you own the bind

	conn := libtunnel.New(libtunnel.Cloudflare(), libtunnel.QuickTunnel()).
		WithListener(l) // lazily starts the edge connection

	go http.Serve(conn.Listener(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from libtunnel")
	}))

	<-conn.TunnelReady()
	fmt.Println(conn.URL()) // https://<something>.trycloudflare.com/
}
```

(The Cloudflare ingress dials the origin over https, so the listener should
speak TLS — a self-signed certificate is enough; see
[`examples/serve/main.go`](./examples/serve/main.go).)

## Layout

Three packages, stable/alpha versioning:

```
github.com/cnuss/libtunnel                      — root façade: New, backends,
                                                  providers, handoff helpers.
github.com/cnuss/libtunnel/v1                   — stable Tunnel[T]/Connected[T]/
                                                  Provider[T]/Backend[T] contract
                                                  + CloudflareSpec.
github.com/cnuss/libtunnel/v1alpha1             — lazy tunnel core + generic
                                                  providers. May change between
                                                  alpha revisions.
github.com/cnuss/libtunnel/v1alpha1/cloudflare  — the cloudflared quick-tunnel
                                                  engine.
```

Application code imports the root (`libtunnel.New(...)`). Code that needs to
declare types against the interfaces imports `v1`. Direct access to the
implementation lives in `v1alpha1`.

For the file-by-file map, see
[CONTRIBUTING.md → Where to find things](./CONTRIBUTING.md#where-to-find-things).

## API at a glance

```go
// configurable phase — mutators chain until WithListener narrows the type
type Tunnel[T Spec] interface {
    Connected[T]
    WithLogger(log *slog.Logger) Tunnel[T]    // default: silent
    WithListener(l net.Listener) Connected[T] // starts the connection
}

// post-WithListener phase — observers and lifecycle only
type Connected[T Spec] interface {
    LocalIP() net.IP // local side, inferred from the listener
    LocalPort() int
    LocalHost() string
    LocalURL() *url.URL
    Listener() net.Listener

    Host() string // public side, derived from the spec
    Hostname() string
    Domain() string
    Port() int
    URL() *url.URL // blocks until the hostname resolves publicly
    CACerts() []*x509.Certificate
    Spec() T

    TunnelReady() <-chan struct{}   // connection up + hostname resolves
    HostnameReady() <-chan struct{} // hostname resolves on authoritative NS
}

type Provider[T Spec] interface { Spec(ctx context.Context) (T, error) }
type Backend[T Spec] interface { Name() string } // opaque; engines are alpha-internal
type Spec interface { GetHostname() string }

// façade
func New[T v1.Spec](backend v1.Backend[T], provider v1.Provider[T]) v1.Tunnel[T]
func Cloudflare() v1.Backend[*v1.CloudflareSpec] // in-process cloudflared engine
func QuickTunnel() *cloudflare.QuickTunnelProvider // mints *.trycloudflare.com
func Env[...](next v1.Provider[T]) v1.Provider[T] // adopt TUNNEL_SPEC, else next
func Static[T v1.Spec](spec T) v1.Provider[T]     // replay known credentials

// parent→child handoff
const SpecEnv = "TUNNEL_SPEC"
func ExportSpec[T v1.Spec](spec T) error            // os.Setenv for re-exec
func SpecEnviron[T v1.Spec](spec T) (string, error) // entry for exec.Cmd.Env
func SpecFromEnv[T v1.Spec](spec T) (bool, error)   // child-side read
```

## Parent→child handoff

`TUNNEL_SPEC` is a first-class handoff channel: a parent process mints a
tunnel spec, a child process receives it through the environment, provides
the listener, and the tunnel connects under the same hostname — no second
quick-tunnel resolution.

```go
// parent: mint and hand off (never connects itself)
spec := libtunnel.New(libtunnel.Cloudflare(), libtunnel.QuickTunnel()).Spec()
entry, _ := libtunnel.SpecEnviron(spec)
cmd.Env = append(os.Environ(), entry)

// child: adopt and connect
conn := libtunnel.New(libtunnel.Cloudflare(), libtunnel.Env(libtunnel.QuickTunnel())).
	WithListener(l)
```

(Full source: [`examples/handoff/main.go`](./examples/handoff/main.go).)

## Examples

Self-contained programs in [`./examples`](./examples):

| Example   | Demonstrates                                                       |
| --------- | ------------------------------------------------------------------ |
| `offline` | Spec handoff + lazy getters, no network access.                     |
| `serve`   | Real quick tunnel: serve HTTPS locally, request the public URL.     |
| `handoff` | Parent mints a spec; child adopts it via `TUNNEL_SPEC` and serves.  |

Run one locally:

```sh
make run offline
make run serve
make run handoff
```

## Testing

```sh
make test   # library unit + fuzz tests (fast, in-package)
make e2e    # builds and runs the example binaries, asserts their output
```

`make e2e` runs `go test -count=1 -v ./e2e`. The `-count=1` defeats the test
cache, since the harness builds the example binaries at runtime and the cache
key wouldn't otherwise pick up example source changes.

The `serve` and `handoff` examples mint real tunnels from
`api.trycloudflare.com` (rate-limited), so the e2e harness skips them unless
you opt in:

```sh
LIBTUNNEL_E2E_LIVE=1 make e2e
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the local dev loop, release
process, and what makes a good example.

## License

[MIT](./LICENSE)
