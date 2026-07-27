# A TypeScript libtunnel, from the same repo

**Date:** 2026-07-27
**Status:** design, pending prototype gates

## Goal

Ship a TypeScript library from this repository alongside the Go one: same
public API shape, same fluent builder, same wire behavior — a different engine
underneath. The Go module is untouched. A `package.json` and a `src/` tree
join it at the root.

The TypeScript engine is a native reimplementation of the cloudflared
connector protocol on Node primitives. It does not spawn the `cloudflared`
binary, the `cmd/libtunnel` binary, or any other subprocess, and it links no
native addon. It carries cloudflared's own protocol selection —
`auto` / `quic` / `http2`, defaulting to `auto`, preferring QUIC.

## What the Go engine actually does

Five steps, all in `v1alpha1/cloudflare/cloudflare.go`:

1. **Mint** — `POST https://api.trycloudflare.com/tunnel` returns
   `{id, hostname, account_tag, secret}`. Plain HTTP.
2. **Edge discovery** — SRV lookup on `_v2-origintunneld._tcp.argotunnel.com`
   yields regional edge hosts; connections go to port 7844.
3. **Transport** — TLS to an edge address. Two protocols: `quic` (ALPN
   `argotunnel`, SNI `quic.cftunnel.com`) and `http2` (TCP, SNI
   `h2.cftunnel.com`, ALPN `h2`). cloudflared's own selector is
   `ProtocolList = [QUIC, HTTP2]` with QUIC falling back to HTTP2.
4. **Register** — Cap'n Proto RPC over a control stream. The interface is
   three methods: `registerConnection(auth, tunnelId, connIndex, options)`,
   `unregisterConnection()`, `updateLocalConfiguration(config)`.
5. **Serve** — the edge pushes requests in; the connector proxies them to the
   origin.

## Protocol selection

The backend carries cloudflared's `--protocol` knob:
`withProtocol('auto' | 'quic' | 'http2')`, default `auto`, mirrored by
`LIBTUNNEL__CLOUDFLARE_PROTOCOL` under the existing backend-scoped env
pattern. Semantics match cloudflared:

- **`auto`** (default) — prefer QUIC, fall back to HTTP/2. In TypeScript this
  additionally means a *capability probe*: if the runtime cannot provide QUIC,
  warn once through the tunnel logger and select HTTP/2.
- **`quic`** — QUIC only. If the runtime cannot provide it, fail loudly. No
  silent fallback, matching cloudflared's `staticProtocolSelector`, whose
  `Fallback()` returns `(current, false)`.
- **`http2`** — HTTP/2 only, no probe.

### The QUIC capability probe

`node:quic` is the QUIC binding, and its API is a precise fit:

```js
const session = await connect('1.2.3.4:7844', {
  alpn: 'argotunnel',          // cloudflared's quicProtos
  sni:  'quic.cftunnel.com',   // cloudflared's edgeQUICServerName
  ca:   cloudflareRoots,
})
const stream = await session.createBidirectionalStream()
session.sendDatagram(buf)      // datagram-v3, later
```

The catch, verified rather than assumed: `--experimental-quic` is documented
as a runtime flag, but it is *also* a build-time configure flag, and stock
Node ships without the build side. On the official v25.9.0 release build:

```
$ node --experimental-quic -e "require('node:quic')"
ERR_UNKNOWN_BUILTIN_MODULE: No such built-in module: node:quic
$ node -p "process.config.variables.node_use_quic"
false
$ node --help | grep -i quic          # nothing
```

`nodejs.org/api/quic.html` returns 404 while the nightly documentation carries
a full QUIC page. So `node:quic` is nightly-or-custom-build only today.

The probe therefore tests *capability*, not a flag:

1. `process.config.variables.node_use_quic` is truthy, and
2. a guarded dynamic `import('node:quic')` resolves.

Both pass, QUIC is selected. Either fails under `auto`, the tunnel logs one
warning naming the reason and continues on HTTP/2 — the caller gets a working
tunnel either way. Under an explicit `quic` the same failure is fatal.

A consequence worth stating plainly: **HTTP/2 is not a later milestone.** It
is the fallback leg of the default path, so both transports land together in
M1, and on stock Node today HTTP/2 is what nearly every user will actually
run.

### Why not polyfill QUIC

Two routes exist and both are deferred, not dismissed:

- **A native addon over Cloudflare's quiche.** `@matrixai/quic` works, but its
  latest publish is March 2025 and its prebuild matrix has no linux-arm64
  (`@infisical/quic` is a fork that added arm). Taking it reintroduces a
  semi-abandoned native dependency, against the premise of this library.
- **`quinn-proto` compiled to WASM, with UDP via `node:dgram`.** `quinn-proto`
  is sans-I/O — a deterministic state machine over byte buffers that never
  touches a socket — so WASM handles crypto and state while `node:dgram`
  handles packets. `Frando/quinn-wasm` demonstrates it compiles, with patches
  to quinn and rustls; `wasm32-unknown-unknown` lacks `Instant` and
  `SystemTime`, which a sans-I/O design lets us inject from JS. Pure npm, no
  native build — and a large enough project to deserve its own spec.

Either could later slot in behind the same probe as a third candidate, ahead
of the HTTP/2 fallback, without touching the public API.

### Cost of the HTTP/2 leg

TCP head-of-line blocking means measurably worse throughput under packet loss
than QUIC. That belongs in the TypeScript README, not in someone's incident
review.

## Naming

`cloudflare()` is kept in the TypeScript API, matching Go.

This is not merely cosmetic consistency. The spec envelope is tagged with the
backend name (`backendName = "cloudflare"`, `v1alpha1/cloudflare/cloudflare.go:67`)
and a child running a different backend fails loudly rather than silently
unmarshaling a foreign spec. The `LIBTUNNEL__CLOUDFLARE_*` variables are the
same kind of contract. Cross-language handoff requires both to match
byte-for-byte, so renaming the TypeScript identifier while keeping the wire
tag would put a seam between the name a caller writes and the name that
travels — for no gain.

## Repo shape

`package.json` and `src/` at the root. The Go tree is untouched.

```
libtunnel/
  go.mod  go.sum  lib.go  v1/  v1alpha1/  cmd/  examples/  e2e/
  package.json  tsconfig.json
  src/
    index.ts              facade: tunnel() cloudflare() from() hosts() version()
    v1/index.ts           types + env constant table    <- mirrors v1/v1.go
    v1alpha1/
      tunnel.ts           lazy core
      provider.ts         env -> overlay -> replay -> mint chain
      from.ts             spec cache: from(), hosts()
      intercept.ts        InterceptCtx
      resolver.ts         authoritative-NS hostname resolver
      cloudflare/
        index.ts  spec.ts  quicktunnel.ts
        transport/
          index.ts        Transport interface + protocol selector + probe
          quic.ts         engine #1, node:quic
          http2.ts        engine #2, fallback leg
          discovery.ts    SRV lookup
          registration.ts capnp RegistrationServer client
          framing.ts      quic-pogs stream signatures + ConnectRequest
          roots.ts        Cloudflare origin roots, vendored PEM
        capnp/            generated from tunnelrpc.capnp + quic_metadata_protocol.capnp
    bin/libtunnel.ts      env-only launcher <- mirrors cmd/libtunnel
  testdata/               shared conformance fixtures, read by both languages
```

The TypeScript tree mirrors the Go package split (`v1` types, `v1alpha1`
implementation, backend under it) so parity stays auditable file by file
rather than by reading both libraries end to end.

One tooling note: `go list ./...` does *not* ignore `node_modules` — verified
empirically. This is harmless in practice, since npm packages do not ship
`.go` files, but `gofmt -l .` walks the whole tree, so the `fmt` and
`fmt-check` Makefile targets need an explicit prune.

## API mapping

| Go | TypeScript |
| --- | --- |
| `New(b)` `Cloudflare()` `From(s)` `Hosts()` `Version()` | `tunnel(b)` `cloudflare()` `from(s)` `hosts()` `version()` |
| `LocalPort` `LocalIP` `LocalHost` `LocalURL` | `localPort()` `localIP()` `localHost()` `localURL()`, each `Promise` |
| `Host` `Hostname` `Domain` `Port` | same, camelCased, each `Promise` |
| `CACerts() []*x509.Certificate` | `caCerts(): Promise<string[]>`, PEM |
| `Listener() net.Listener` | `server(): http.Server` |
| `URL() *url.URL` | `url(): Promise<URL \| null>` |
| `HostnameReady()` `TunnelReady()` `Done()` | `hostnameReady()` `tunnelReady()` `done()`, each `Promise<void>` |
| `Err() error` | `err(): Error \| null`, sync |
| `WithContext(ctx)` | `withSignal(signal: AbortSignal)` |
| `WithListener(l)` | `withServer(s: net.Server)` |
| `WithLocalURL` `WithLogger` `WithInterceptor` `Interceptors` | camelCased, unchanged |
| backend `WithTLS` `WithHTTP2` `WithID` `WithName` `WithHostname` `WithAccountTag` `WithSecret` `WithProvider` | camelCased, unchanged |
| *(no Go equivalent)* | `withProtocol('auto' \| 'quic' \| 'http2')` |

Blocking getters become async methods keeping their Go names. Channels become
Promises — a channel closed exactly once is a Promise resolved exactly once.
`err()` stays synchronous, null while the tunnel is alive.

```ts
const conn = tunnel(cloudflare())
  .withSignal(ac.signal)
  .withServer(srv)

await conn.tunnelReady()
const url = await conn.url()
await conn.done()
const e = conn.err()
```

`server()` mints a loopback `http.Server` on 127.0.0.1:0 when no origin was
provided, is a start trigger, and closing it closes the tunnel — matching
`Listener()`. Node has no bare listener type, so `net.Server` is the analog
for `withServer`.

The write-once discipline carries over unchanged: each `with*` mutator takes
effect at most once and is a no-op after its value is fixed, whether by an
earlier call or by the tunnel's first use of the default. Providing the origin
twice cancels the tunnel.

### One asymmetry, deliberately

`withProtocol` has no Go counterpart: the Go backend hardcodes
`connection.NewProtocolSelector("auto", ...)` and exposes no knob. Adding
`WithProtocol` plus `LIBTUNNEL__CLOUDFLARE_PROTOCOL` to the Go backend would
restore symmetry and is a small, self-contained change — but it is a change to
Go code, which this experiment is explicitly not making. Filed as a follow-up
rather than smuggled in here.

### Interceptors

`handler()` is `(req: IncomingMessage, res: ServerResponse) => void`, so
ordinary connect/express middleware drops in unmodified. Go's `InterceptCtx`
embeds `context.Context`; the TypeScript one exposes `ic.signal`. Priority
semantics are unchanged: ALB-style, lowest wins, 1 is the highest settable
precedence, 0 means unset and is auto-assigned from the top of the `uint16`
range downward.

### Logger

A structural interface — `{debug, info, warn, error}(msg, fields?)` — which
`console`, pino, and winston all satisfy without an adapter. `LIBTUNNEL_LOG`
carries a level, not a sink, exactly as in Go.

## Engine

### Transport interface

Mirrors cloudflared's `ProtocolSelector`: an ordered candidate list, a
capability probe, and a fallback chain. Both implementations satisfy one
interface, so the selector is the only code that knows which is running.

### QUIC transport (engine #1)

1. SRV discovery as below, then `connect('<addr>:7844', {alpn: 'argotunnel',
   sni: 'quic.cftunnel.com', ca})` via `node:quic`.
2. **RPC stream** — open a bidirectional stream, write the 6-byte signature
   `52 BB 82 5C DB 65`, then speak capnp RPC: `registerConnection`. Success
   emits Connected, satisfying the edge half of `tunnelReady`.
3. **Data streams** — the edge opens a bidirectional stream per request
   carrying the 6-byte signature `0A 36 CD 12 A1 3E`, one version byte, then a
   capnp `ConnectRequest{dest, type: http|websocket|tcp, metadata[]}`. HTTP
   headers ride in `metadata` as key/val pairs. We reply with a signature
   preamble plus capnp `ConnectResponse`, then stream the body.
4. `reconnect()` closes the session and re-dials, waiting for N Connected
   events past the pre-send count — a direct port of `edgeUpWatcher`.

Datagram support (`sendDatagram` / `ondatagram`, cloudflared's datagram-v3 for
UDP) is out of scope: libtunnel exposes no UDP surface.

### HTTP/2 transport (engine #2, the fallback leg)

1. `net.connect(addr, 7844)`, then `tls.connect({socket, servername:
   'h2.cftunnel.com', ALPNProtocols: ['h2']})`.
2. Run an HTTP/2 **server** over that socket. We are the server; the edge is
   the client.
3. Dispatch each stream on `Cf-Cloudflared-Proxy-Connection-Upgrade`:
   `control-stream` hands the stream to the capnp client for
   `registerConnection`; `websocket` strips the header and proxies as a
   websocket; `update-configuration` applies and acknowledges; anything else
   is an ordinary request into the interceptor pipeline.
4. `reconnect()` closes the h2 session and re-dials, same barrier as above.

No signature framing on this path — requests arrive as ordinary h2 streams
Node already parses. This is why the fallback leg is the cheaper one to build.

### Shared: discovery, registration, roots

`dns.resolveSrv('_v2-origintunneld._tcp.argotunnel.com')`, then A/AAAA, gives
edge addresses on port 7844 for both transports.

Registration is one capnp RPC client used by both, differing only in which
stream it is handed.

Node ships Mozilla's bundle as `tls.rootCertificates`, so only cloudflared's
Cloudflare origin roots need vendoring as PEM in `transport/roots.ts`.

### The loopback hop is kept

Go interposes a loopback reverse proxy because cloudflared needs a URL to
dial. The TypeScript transports are in-process and could call the interceptor
chain directly, but the hop is kept deliberately: the transport dials
127.0.0.1 like cloudflared does, so `InterceptCtx.target()` means precisely
what it means in Go, including its "close it to force a re-dial" lever, which
has a real mechanism behind it rather than being a preserved shape. Every
method maps 1:1 with no asterisk. The cost is one local TCP round trip per
request, which the Go engine also pays.

## Prototype gates

Three unknowns are load-bearing, each answerable independently of the rest of
the library.

**G1 — HTTP/2 over a pre-established TLS socket.** Node's http2 server is
normally handed a listening socket. Feeding it an already-negotiated TLS
socket (`http2.createServer()` plus `emit('connection', socket)`) is
undocumented usage. The entire fallback leg — which is what most users will
run — rests on it.

**G2 — Cap'n Proto in JavaScript.** Two halves. The metadata schemas
(`ConnectRequest` / `ConnectResponse`) are plain serialization and should be
straightforward. RPC level 1, needed for registration on both transports, is
supported by `capnp-es` but marked experimental at 0.0.14. Fallback is
hand-rolling three message encodings, bounded work given the interface is
three methods.

**G3 — `node:quic` against the real edge.** On a QUIC-capable Node build,
does `connect()` with `alpn: 'argotunnel'` and `sni: 'quic.cftunnel.com'`
reach an edge address and carry a bidirectional stream? This also establishes
the CI lane the QUIC path is tested on.

If G1 fails, the fallback leg is dead and with it most of the practical value.
If G3 fails, QUIC waits for a polyfill and the library is HTTP/2-only. Either
answer arrives in an afternoon rather than four weeks in.

## Testing

Three tiers, mirroring the Go layout.

**Unit** — `node:test`, no test-framework dependency, matching the Go side's
zero-dep posture. Provider chain resolution order, spec envelope round-trip,
Priority auto-assignment, env-mirror precedence, `from`/`hosts` cache,
resolver, and the protocol probe's decision table (including that `auto` warns
once and falls back, and that explicit `quic` fails loudly).

**Cross-language conformance** — shared fixtures under `testdata/`, asserted
byte-identically by `go test` and `node:test`: spec envelopes, the
tagged-backend guard, the env-precedence table. This is what keeps the two
implementations from becoming two libraries wearing the same costume.

**Live e2e** — in `e2e/`, gated by `LIBTUNNEL_E2E_LIVE=1` as today. TypeScript
mints a real quick tunnel and fetches through it, run once per transport by
pinning `withProtocol`. Handoff is tested in both directions: a Go parent
mints and a TypeScript child adopts `LIBTUNNEL_SPEC` and serves, and the
reverse. That test failing is the clearest available signal that the
implementations have drifted.

## CI and release

`ci.yml` gains a Node job (node 20/22/24 across ubuntu/macos/windows)
alongside the existing Go matrix. Node floor is `>=20`.

It also gains a **QUIC lane**: a Node nightly (or a Node built with
`--experimental-quic`) on ubuntu only, running the QUIC-pinned subset. Without
it the QUIC transport ships compiled but unexercised, which for a network
transport means probably broken. The lane is allowed to fail without blocking
the merge — it tracks an unstable upstream — but its failures are visible
rather than absent.

Release stays a single tag and a single stream: the existing workflow adds an
`npm publish --provenance` step, so `Version()` and the npm package version
cannot disagree — which matters, because cross-language handoff then can never
be a version mismatch. A TypeScript-only fix burns a Go version number and
vice versa, which is acceptable at the current 0.0.x cadence.

`libtunnel` is unclaimed on npm.

## Milestones

| | Scope | Done when |
| --- | --- | --- |
| M0 | Prototype gates G1, G2, G3 | go/no-go on the native premise, per transport |
| M1 | discovery, both transports, selector + probe, registration, mint | a real public URL served from pure TypeScript, over QUIC on a QUIC-capable Node and over HTTP/2 on a stock one |
| M2 | full v1 surface | lazy getters, write-once mutators, interceptors, resolver, spec cache, handoff, env mirrors |
| M3 | TypeScript CLI, npm release wiring, conformance e2e | shippable |

M0 through M3 are one implementation plan. A QUIC polyfill — WASM or napi —
is a separate project with its own spec, undertaken only if `node:quic` stays
out of stable Node releases long enough to matter.

## Risks

1. **G1.** Undocumented Node usage that the fallback leg depends on, and the
   fallback leg is what most users run.
2. **`node:quic` is nightly-only and Stability 1.0.** The API can change under
   us, and the QUIC path reaches almost no real users until Node ships it in a
   release build. Mitigated by the probe: nobody gets a broken tunnel, they
   get HTTP/2 and a warning.
3. **Cloudflare deprecating the `http2` protocol.** It is the UDP-blocked
   fallback, so it has a constituency, but it is the older path and this
   library would lean on it harder than cloudflared does.
4. **capnp-es RPC is experimental.** Bounded fallback: hand-roll three
   messages.
5. **Throughput under packet loss** on the HTTP/2 leg. Real, measurable, and
   unfixable without QUIC — so it belongs in the README.

## Out of scope

- Replacing or modifying any Go code. The Go module is untouched. (Adding
  `WithProtocol` to the Go backend for symmetry is a filed follow-up, not part
  of this work.)
- Datagram-v3 / UDP. libtunnel exposes no UDP surface.
- A JavaScript reimplementation of the Cloudflare API beyond the quick-tunnel
  mint endpoint.
- Named tunnels, Access, WARP routing, or any cloudflared surface libtunnel
  does not already expose.
