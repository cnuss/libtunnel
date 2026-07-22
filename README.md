# libtunnel

[![Go Reference](https://pkg.go.dev/badge/github.com/cnuss/libtunnel.svg)](https://pkg.go.dev/github.com/cnuss/libtunnel)
[![Go Report Card](https://goreportcard.com/badge/github.com/cnuss/libtunnel)](https://goreportcard.com/report/github.com/cnuss/libtunnel)
[![CI](https://github.com/cnuss/libtunnel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/cnuss/libtunnel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/cnuss/libtunnel/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/cnuss/libtunnel/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cnuss/libtunnel/badge)](https://scorecard.dev/viewer/?uri=github.com/cnuss/libtunnel)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

`libtunnel` exposes a local origin to the public internet through a tunnel
backend — Cloudflare quick tunnels first, driven entirely in-process (no
`cloudflared` binary required).

The API is pure-lazy: every getter resolves on first use, and the edge
connection starts on first demand — `WithListener` provides the origin
listener explicitly, `WithLocalURL` points at an already-running local origin
instead (the `cloudflared tunnel --url` shape), and `Listener`, `URL`, and
`TunnelReady` mint a loopback listener if no origin was provided.
Configuration is write-once: each `With*` mutator takes effect at most once
and is a no-op after its value is fixed, whether by an earlier call or by the
tunnel's first use of the default.

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
github.com/cnuss/libtunnel/v1                   — stable Tunnel +
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
// the lazy tunnel handle — every getter resolves on first use; the tunnel
// starts on first demand. Non-generic: the spec type is a construction-time
// detail, so a tunnel reference stores without threading T through caller code.
type Tunnel interface {
    LocalPort() int  // local side, inferred from the origin (listener or URL)
    LocalIP() net.IP
    LocalHost() string
    LocalURL() *url.URL

    Host() string // public side, derived from the spec
    Hostname() string
    Domain() string
    Port() int
    CACerts() []*x509.Certificate

    Listener() net.Listener // start trigger: mints a loopback listener if none provided
    URL() *url.URL // blocks until the hostname resolves (end-to-end w/ WithContext);
                   // start trigger, like Listener

    HostnameReady() <-chan struct{} // hostname resolves on authoritative NS
    TunnelReady() <-chan struct{}   // connection up + hostname resolves;
                                    // start trigger, like Listener
    Done() <-chan struct{}          // tunnel failed or shut down
    Err() error                     // why (nil while alive)

    // write-once mutators: first call wins, no-ops once the value is fixed
    WithLogger(log *slog.Logger) Tunnel      // default: silent
    WithContext(ctx context.Context) Tunnel  // URL waits end-to-end, honors ctx
    WithListener(l net.Listener) Tunnel      // bring your own listener
    WithLocalURL(u *url.URL) Tunnel          // attach to a running local origin
                                             // (http://localhost:1234); mutually
                                             // exclusive with WithListener
}

type Provider[T Spec] interface { Spec(ctx context.Context) (T, error) }
type Backend[T Spec] interface { // opaque; the engine contract is alpha-internal
    Name() string
    Provider() Provider[T] // the backend's credential chain
}
type Spec interface {
    GetHostname() string
    Serialize() string // tagged-envelope JSON; == a LIBTUNNEL_SPEC value
}

// façade
func New[T v1.Spec](backend v1.Backend[T]) v1.Tunnel // T wires the backend, not the result
func Cloudflare() v1.Backend[*cloudflare.Spec]   // in-process cloudflared engine;
                                                 // adopts LIBTUNNEL_SPEC, else mints
                                                 // an anonymous quick tunnel
func From(spec string) v1.Tunnel                 // replay a serialized spec (JSON,
                                                 // file path, or cached hostname)
func Hosts() []string                            // public URLs of cached specs

// parent→child handoff — no API: minting exports the LIBTUNNEL_SPEC env var,
// construction adopts it
```

## Parent→child handoff

`LIBTUNNEL_SPEC` is a first-class handoff channel with nothing to call: when
the Cloudflare credential chain mints a spec it exports it into the
process's environment, and at construction it adopts one found there. A
spawned child (or a re-exec) therefore connects under the same hostname —
no second quick-tunnel resolution, no plumbing. The export also sets
`LIBTUNNEL_HOSTNAME` to the plain hostname, so tooling can read it without
parsing the envelope (libtunnel itself adopts `LIBTUNNEL_SPEC`, not this).

Two guardrails keep the channel safe: a process never re-adopts a spec it
exported itself (a second tunnel in the same process mints its own identity
instead of inheriting the first one's), and the exported value is tagged
with the backend that minted it, so a child running a different backend
fails loudly instead of silently unmarshaling a foreign spec.

```go
// parent: forcing the mint exports LIBTUNNEL_SPEC as a side effect (never
// connects itself); Hostname triggers the mint and returns the public name
libtunnel.New(libtunnel.Cloudflare()).Hostname()
cmd := exec.Command(os.Args[0], "child") // inherits the environment

// child: the Cloudflare credential chain finds LIBTUNNEL_SPEC and adopts it
conn := libtunnel.New(libtunnel.Cloudflare()).WithListener(l)
```

(Full source: [`examples/subprocess/main.go`](./examples/subprocess/main.go).)

## Replaying a spec

A freshly minted spec is cached to disk as `<hostname>.spec.json` (the
`Serialize()` envelope, same form as `LIBTUNNEL_SPEC`) under the cache dir —
`LIBTUNNEL_CACHE_DIR` if set, else a per-user location from `os.UserCacheDir()`.
`libtunnel.Hosts()` lists the cached tunnels as `https://<host>:443/` URLs, and
`libtunnel.From(spec)` replays one — `spec` is the JSON, a file path, or just a
cached hostname — connecting under the same hostname instead of minting. Only
minted specs are cached (adopted or `From`-loaded ones are not), and a
bad/unknown spec yields a tunnel already canceled with the cause (off `Err()`).

```go
// replay the most recently cached tunnel by hostname
conn := libtunnel.From("foo.trycloudflare.com").WithListener(l)
```

## Environment variables

Every code knob with an env-expressible value has an environment mirror, and
**env beats code**: an operator can redirect a deployed binary without a
rebuild. (The one exception is noted below.)

| Variable | Mirrors | Behavior |
| -------- | ------- | -------- |
| `LIBTUNNEL_SPEC` | — | Parent→child handoff: a serialized spec adopted at construction (see above). Beats everything, including a code-pinned `From` spec. |
| `LIBTUNNEL_FROM` | `From()` | Replay a spec by hostname, file path, or literal JSON — `From`'s resolution. Applies after `LIBTUNNEL_SPEC`, before the code-pinned spec and minting. |
| `LIBTUNNEL_LOCAL_URL` | `WithLocalURL()` | Origin override, applied at origin-provide time: supersedes a `WithListener` listener, a `WithLocalURL` argument, and the start-trigger mint. Invalid value cancels the tunnel. |
| `LIBTUNNEL_TLS` | `WithTLS()` | Bool (`strconv.ParseBool`). Fixed at backend construction; later `WithTLS` calls are no-ops. Unparsable value fails at connect. |
| `LIBTUNNEL_HTTP2` | `WithHTTP2()` | Same rules as `LIBTUNNEL_TLS`. |
| `LIBTUNNEL_LOG` | `WithLogger()` | `debug`\|`info`\|`warn`\|`error`: the default logger becomes a stderr text logger at that level instead of silent. *The exception:* an explicit `WithLogger` keeps its handler — env carries a level, not a sink. |
| `LIBTUNNEL_HOSTNAME` | — | Export-only mirror of the minted spec's hostname, for tooling; never adopted. |
| `LIBTUNNEL_CACHE_DIR` | — | Where minted specs are cached and `From`/`Hosts` look. |

Backend-scoped variables follow `LIBTUNNEL__<BACKEND>_<FIELD>` (double
underscore namespaces the backend) and live with their backend package. For
Cloudflare, each mirrors a spec-field setter on the backend — env beats code,
field by field, patched onto whatever spec the chain resolves; a complete
credential set (id, hostname, account tag, secret) skips resolution entirely:

| Variable | Mirrors |
| -------- | ------- |
| `LIBTUNNEL__CLOUDFLARE_ID` | `WithID()` |
| `LIBTUNNEL__CLOUDFLARE_NAME` | `WithName()` |
| `LIBTUNNEL__CLOUDFLARE_HOSTNAME` | `WithHostname()` |
| `LIBTUNNEL__CLOUDFLARE_ACCOUNT_TAG` | `WithAccountTag()` |
| `LIBTUNNEL__CLOUDFLARE_SECRET` | `WithSecret()` (base64) |
| `LIBTUNNEL__CLOUDFLARE_API_URL` | `WithApiURL()` — quick-tunnel mint endpoint, default `https://api.trycloudflare.com/tunnel` |

The Cloudflare backend also has a bare activation switch, `LIBTUNNEL__CLOUDFLARE=1`,
used by the binary below to select it without a spec handoff.

## Binary

[`cmd/libtunnel`](./cmd/libtunnel) is a standalone launcher configured
**only** by the environment — no flags, no config files — the operator-side
face of the variables above. Shaped for `docker run -e ...`:

```sh
go run ./cmd/libtunnel
# or: go build -o libtunnel ./cmd/libtunnel
```

It needs two things:

- a **backend**, activated by `LIBTUNNEL_SPEC` (a spec handoff) or
  `LIBTUNNEL__CLOUDFLARE=1` (the explicit switch); and
- an **origin**, `LIBTUNNEL_LOCAL_URL` — a standalone binary has no listener
  to inherit, so it points at an already-running local service.

```sh
LIBTUNNEL__CLOUDFLARE=1 \
LIBTUNNEL_LOCAL_URL=http://localhost:8080 \
LIBTUNNEL_LOG=info \
  libtunnel
```

It prints the public URL to stdout (one line; logs go to stderr via
`LIBTUNNEL_LOG`) and runs until `SIGINT`/`SIGTERM`. Every other knob —
`LIBTUNNEL_TLS`, `LIBTUNNEL_FROM`, the `LIBTUNNEL__CLOUDFLARE_*` fields —
flows straight through the library. Minting also exports
`LIBTUNNEL_SPEC`/`LIBTUNNEL_HOSTNAME`, so a child it later spawns inherits the
same tunnel identity. `libtunnel version` prints the build id and exits — the
only argument it accepts, since configuration is environment-only.

Each release attaches static, stripped binaries for linux/darwin/windows ×
amd64/arm64, a `SHA256SUMS` manifest, and a cosign `.sigstore` bundle per
file. To build locally instead: `make dist` (cross-compiles the matrix into
`dist/`) or `make binary` (host only). CGO is off, so the binary is
dependency-free and runs on a scratch/distroless base — [`Dockerfile`](./Dockerfile)
targets `distroless/static:nonroot`. Each release publishes a multi-arch
(amd64/arm64), cosign-signed image to the GitHub Container Registry:

```sh
docker run --rm \
  -e LIBTUNNEL__CLOUDFLARE=1 \
  -e LIBTUNNEL_LOCAL_URL=http://host.docker.internal:8080 \
  ghcr.io/cnuss/libtunnel:latest
```

Or build it yourself: `docker build -t libtunnel .`

## Examples

Self-contained programs in [`./examples`](./examples):

| Example   | Demonstrates                                                       |
| --------- | ------------------------------------------------------------------ |
| `serve`   | Real quick tunnel: serve locally, request the public URL.           |
| `serve-tls` | Same as `serve`, but a TLS listener (`tls.Listen`) — ingress flips to https. |
| `subprocess` | Parent mints a spec; child adopts it via `LIBTUNNEL_SPEC` and serves. |

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
