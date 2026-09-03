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
listener explicitly, `WithLocalURL` points at one or more already-running
local origins instead (the `cloudflared tunnel --url` shape; extra origins are
reachable per request via a bare `?n` query parameter — assets and iframes
follow their document URL via Referer, top-level visits stick via cookie),
and `Listener`, `URL`, and `TunnelReady` mint a loopback listener if no origin
was provided.
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
	fmt.Println(url) // https://<something>.tunneled.pizza/
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
    Err() error                     // why (nil while alive); see Failure classes

    // write-once mutators: first call wins, no-ops once the value is fixed
    WithLogger(log *slog.Logger) Tunnel      // default: silent
    WithContext(ctx context.Context) Tunnel  // URL waits end-to-end, honors ctx
    WithListener(l net.Listener) Tunnel      // bring your own listener
    WithLocalURL(u ...*url.URL) Tunnel       // attach to running local origins
                                             // (http://localhost:1234); mutually
                                             // exclusive with WithListener; u[0]
                                             // is the default, ?n routes to u[n]
                                             // (sticky cookie, param dropped;
                                             // WebSockets need the app's help
                                             // — see below)

    // hook requests in front of the origin proxy; layerable, not write-once
    WithInterceptor(interceptor Interceptor) Tunnel
    Interceptors() Interceptors // snapshot in precedence order (ascending Priority)
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
func Version() string                            // the libtunnel release this build
                                                 // links against (matches the git tag
                                                 // and the container image tag)

// parent→child handoff — no API: minting exports the LIBTUNNEL_SPEC env var,
// construction adopts it
```

## Failure classes

A tunnel that will not come up ends with a class off `Err()`, so a caller
branches on the failure rather than on the text of a message it did not write:

```go
switch {
case errors.Is(conn.Err(), libtunnel.ErrCertificate):
    // no CA bundle, a wrong clock, or an intercepting proxy
case errors.Is(conn.Err(), libtunnel.ErrCredentialRejected):
    // the spec you replayed names a tunnel that no longer exists —
    // discard it and mint fresh
case errors.Is(conn.Err(), libtunnel.ErrEdgeUnreachable):
    // egress to port 7844 is blocked — WithEdge routes around it
case errors.Is(conn.Err(), libtunnel.ErrFailed):
    // it will not come up, and the message says why
}
```

| class | meaning | retried for |
| --- | --- | --- |
| `ErrCertificate` | the provider's certificate could not be verified | never |
| `ErrRejected` | the provider said no, or the request could not be built | never |
| `ErrCredentialRejected` | the edge refused these credentials — the tunnel is gone | never |
| `ErrProviderUnreachable` | the mint endpoint refuses, times out or 5xxs | 45s |
| `ErrEdgeUnreachable` | the edge never accepted a connection | 30s |
| `ErrRateLimited` | throttled past its budget, or past its advertised reset | 45s |
| `ErrClosed` | shut down deliberately — terminal, but not a failure | n/a |

Every class except `ErrClosed` answers `errors.Is(err, libtunnel.ErrFailed)`.
Retries are bounded by class rather than by the caller's context, so a mint
that can never succeed fails with a reason instead of hanging.

## Multiple origins

`WithLocalURL` takes more than one URL. `u[0]` is the default; a bare numeric
query parameter picks another, is dropped from the forwarded request, and pins
what follows:

```go
conn := libtunnel.New(libtunnel.Cloudflare()).
    WithLocalURL(api, admin) // https://<host>/ -> api, https://<host>/?1 -> admin
```

Resolution order per request: an explicit `?n`, then a same-host `Referer`
carrying one (so a routed page's assets, XHR, and iframes follow their own
document URL — side-by-side iframes of different origins work in one tab), then
the sticky `libtunnel-origin` cookie set by an explicit top-level pick, then
`u[0]`. A document navigation resolved via `Referer` is redirected to carry the
parameter, so routing survives link clicks.

**WebSockets are the exception.** A handshake carries no `Referer` — it is not
in the handshake header set — so a socket opened without the parameter falls
through to the cookie, which is per-browser, not per-tab or per-iframe. A page
you control can carry the index itself:

```js
new WebSocket("wss://" + location.host + "/sock" + location.search)
```

A third-party dev server's socket (HMR, a notebook kernel, a live-reload
channel) cannot be told to do that. For those, declare which origin owns
WebSockets by marking its scheme — `http+ws`, `http+wss`, `https+ws`,
`https+wss`:

```go
vite, _ := url.Parse("http+ws://localhost:5173")
conn := libtunnel.New(libtunnel.Cloudflare()).WithLocalURL(api, vite)
```

The `ws`/`wss` half is ignored — the suffix induces the designation, and the
origin is dialed by its base scheme exactly as an unmarked one is. The marker
rides on the URL rather than a separate index knob so it cannot drift out of
sync with the origin list: reorder the origins and the designation moves with
them. At most one origin may carry it (two socket-owning origins are
unroutable however they are spelled, so that fails at parse time with both
named), and it is inert with a single origin.

Precedence for a handshake is `?n` → the marked origin → cookie → `u[0]`: an
explicit index still wins, so a page carrying its own — and every tile of a
multiview panel — is unaffected, while an operator-stated fact beats the
per-browser cookie guess. A handshake never writes the cookie, and a socket
that cannot be routed at all is logged at warn naming its own fix, rather than
silently connecting to the wrong origin and leaving the tunnel as the last
thing anybody suspects.

What this does not fix: two socket-using apps behind one tunnel. That needs an
address the browser inherits on its own (a hostname per origin), which is a
backend capability rather than something the proxy can synthesize.

## Interceptors

An in-process reverse proxy always fronts the origin. `WithInterceptor` hooks
that path: for every request the tunnel runs the highest-`Priority` interceptor
whose `MatchFn` returns true; anything unmatched is proxied to the origin
unchanged. Ordering is AWS-ALB style: the **lowest** `Priority` wins — `1` is the
highest precedence, `65535` the lowest. `Priority` 0 is not a precedence; it's
the zero value meaning **unset**, and those are auto-assigned from the top of the
`uint16` range downward, so unprioritized interceptors sit at the low-precedence
end — a later-added one wins over an earlier one, and any explicit `Priority`
outranks them all. Interceptors layer (call it more than once) and, unlike the
write-once `With*` mutators, may be added after the tunnel is live.
`tun.Interceptors()` returns the registry in precedence order for visibility.

```go
type MatchFn     = func(r *http.Request) bool
type InterceptFn = func(ctx InterceptCtx) InterceptCtx

// WithInterceptor takes an Interceptor — the {Match, Handler} pair — so reusable
// interceptors ship as constructors: tun.WithInterceptor(addHeaders()).
type Interceptor struct {
    Match    MatchFn
    Handler  InterceptFn
    Priority uint16 // ALB-style: lowest wins (1 highest); 0 = unset, auto-assigned from the top down
}

// InterceptCtx is the per-request handle. It embeds the request's
// context.Context and carries the request, the response writer, and the
// handler that will serve it — seeded to proxy the origin.
type InterceptCtx interface {
    context.Context

    Reconnect(ctx context.Context) error // cycle the edge conn(s), block until back up
    Target() net.Listener                // the proxy's loopback socket (not the origin)

    WithHandler(h http.HandlerFunc) InterceptCtx // replace the serving handler
    Handler() http.HandlerFunc                   // the handler currently set

    Writer() http.ResponseWriter
    Request() *http.Request
}
```

An `InterceptFn` receives the `InterceptCtx` and shapes how the request is
served: call `WithHandler` to take it over, or return the ctx unchanged (or
`nil`) to leave the default in place — the request is proxied to the origin,
exactly as if nothing had matched. So an interceptor can match broadly, inspect,
and opt out per request.

Ship an interceptor as a constructor that returns an `Interceptor`. The common
shape wraps the default handler (`ic.Handler()`, which proxies to the origin) —
plain net/http middleware:

```go
// addHeader sets a response header on every request, then serves the origin.
func addHeader(key, val string) libtunnel.Interceptor {
    return libtunnel.Interceptor{
        Match: func(*http.Request) bool { return true },
        Handler: func(ic libtunnel.InterceptCtx) libtunnel.InterceptCtx {
            next := ic.Handler() // the default: proxy to the origin
            return ic.WithHandler(func(w http.ResponseWriter, r *http.Request) {
                w.Header().Set(key, val)
                next(w, r)
            })
        },
    }
}

tun := libtunnel.New(libtunnel.Cloudflare()).WithListener(l)
tun.WithInterceptor(addHeader("X-Served-By", "libtunnel"))
```

Reach past the request through the ctx levers — e.g. force an edge reconnect on
`?watch=true`, then serve normally:

```go
func reconnectOnWatch() libtunnel.Interceptor {
    return libtunnel.Interceptor{
        Match: func(r *http.Request) bool { return r.URL.Query().Get("watch") == "true" },
        Handler: func(ic libtunnel.InterceptCtx) libtunnel.InterceptCtx {
            next := ic.Handler()
            return ic.WithHandler(func(w http.ResponseWriter, r *http.Request) {
                ctx, cancel := context.WithTimeout(ic, 30*time.Second)
                defer cancel()
                if err := ic.Reconnect(ctx); err != nil {
                    return // request can't proceed — stop, no further writes
                }
                next(w, r)
            })
        },
    }
}
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

(Live coverage: `TestLiveSpecHandoff` in [`e2e/live_test.go`](./e2e/live_test.go).)

## Replaying a spec

`Serialize()` renders a live tunnel's spec as a tagged-envelope JSON string —
the same form `LIBTUNNEL_SPEC` carries. `libtunnel.From(spec)` replays one:
`spec` is a path to a file holding that JSON, or the JSON itself. A bad or
unknown spec yields a tunnel already canceled with the cause (off `Err()`).

A replay asks the provider for that tunnel rather than assuming it survives —
providers reap idle tunnels, and the provider is the only thing that knows.
What comes back decides the outcome:

| what came back | result |
| --- | --- |
| the same hostname, same tunnel | it connects, unchanged |
| the same hostname, a different tunnel id | it connects — the name is still yours, the tunnel behind it is new |
| a different hostname | `ErrCredentialRejected` — the reservation is gone; discard the spec and mint fresh |
| nothing (the provider cannot be reached) | the spec is replayed as given |

The hostname is the verdict. A provider reclaims by name — hand it the name and
secret a spec was minted under and it answers on that hostname if the
reservation still holds, whatever became of the tunnel behind it. A different
hostname means it could not, so the spec that named the old one is dead.

That last row is what keeps an offline replay working: with a complete
credential set and no network, `From` starts exactly as it did before the check
existed. A spec that turns out to be dead then fails at the edge instead, with
the same `ErrCredentialRejected`.

libtunnel writes nothing to disk. Keeping a spec between runs is the caller's
to do — and a spec is credentials, so store it as such.

```go
// replay the most recently cached tunnel by hostname
conn := libtunnel.From("foo.tunneled.pizza").WithListener(l)
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

Backend-scoped variables follow `LIBTUNNEL__<BACKEND>_<FIELD>` (double
underscore namespaces the backend) and live with their backend package. For
Cloudflare, each mirrors a spec-field setter on the backend — env beats code,
field by field, patched onto whatever spec the chain resolves; a complete
credential set (id, hostname, account tag, secret) skips resolution entirely.
When the chain does mint, the fields known beforehand also ride the mint
request as reclaim hints — `X-Name` and `X-Secret` (base64), the pair that
identifies a reservation — so a
provider that reaps idle tunnels can hand the matching tunnel back instead of
minting fresh. Only fields the caller supplies become hints:

| Variable | Mirrors |
| -------- | ------- |
| `LIBTUNNEL__CLOUDFLARE_ID` | `WithID()` |
| `LIBTUNNEL__CLOUDFLARE_NAME` | `WithName()` |
| `LIBTUNNEL__CLOUDFLARE_HOSTNAME` | `WithHostname()` |
| `LIBTUNNEL__CLOUDFLARE_ACCOUNT_TAG` | `WithAccountTag()` |
| `LIBTUNNEL__CLOUDFLARE_SECRET` | `WithSecret()` (base64) |
| `LIBTUNNEL__CLOUDFLARE_PROVIDER` | `WithProvider()` — quick-tunnel provider host, default `tunnel.pizza` (endpoint `https://<host>/tunnel` synthesized; a value with a scheme is used verbatim) |
| `LIBTUNNEL__CLOUDFLARE_HEADERS` | `WithHeader()` — request headers on the mint call, comma-separated `K=V` (e.g. `X-Opaque=true`, or `X-Ephemeral=true` to mark the mint unreclaimable once reaped); entries beat code per key. No escaping — values can't contain `,` or `=`. Mint-only. |
| `LIBTUNNEL__CLOUDFLARE_EDGE` | `WithEdge()` — comma-separated `host:port` list to dial for the tunnel edge instead of discovering it by SRV (which yields Cloudflare's edge on port 7844). Replaces the code value wholesale; forces the `http2` edge protocol. For reaching the edge through a relay on an allowed port. |

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

The image is tagged with the release version (`v0.0.29`), the bare semver
(`0.0.29`, `0.0`), and `latest`. `libtunnel.Version()` returns the v-prefixed
tag, so a consumer can pin the image to the exact library version it links
against without any string munging:

```go
image := "ghcr.io/cnuss/libtunnel:" + libtunnel.Version()
```

## Examples

Self-contained programs in [`./examples`](./examples):

| Example   | Demonstrates                                                       |
| --------- | ------------------------------------------------------------------ |
| `serve`   | Real quick tunnel: serve locally, request the public URL.           |
| `serve-tls` | Same as `serve`, but a TLS listener (`tls.Listen`) — ingress flips to https. |

Run one locally:

```sh
make run serve
make run serve-tls
```

## Testing

```sh
make test   # library unit + fuzz tests (fast, in-package; -short skips live)
make e2e    # live tier: real tunnels through the real edge
```

`make e2e` runs `go test -count=1 -v ./e2e`. The `-count=1` defeats the test
cache, since the harness builds the example binaries at runtime and the cache
key wouldn't otherwise pick up example source changes. The e2e tier is live
tunnels only — everything mints from `tunnel.pizza` (rate-limited), so the
live cases skip under `-short` (which `make test` passes; offline
spec-handoff coverage lives in the unit tier and always runs), and on CI each
platform runs at most one live tier (see `e2e/util_test.go`).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the local dev loop, release
process, and what makes a good example.

## License

[MIT](./LICENSE)
