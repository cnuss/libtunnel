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
native addon.

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
5. **Serve** — the connector runs an HTTP/2 *server* over the edge connection.
   The edge pushes requests in; the connector proxies them to the origin.

## Why HTTP/2 and not QUIC

Node has no shippable QUIC. `node:quic` remains behind `--experimental-quic`
at Stability 1.0 and is not in a stable release. There is no usable pure-JS
QUIC on npm.

QUIC is polyfillable, by two routes:

- **A native addon over Cloudflare's quiche.** `@matrixai/quic` exists and
  works, but its latest publish is March 2025 and its prebuild matrix has no
  linux-arm64 (`@infisical/quic` is a fork that added arm). Taking it means
  inheriting a semi-abandoned native dependency.
- **A Rust QUIC core compiled to WASM, with UDP via `node:dgram`.**
  `quinn-proto` is sans-I/O — a deterministic state machine over byte buffers
  that never touches a socket — so WASM handles crypto and state while
  `node:dgram` handles packets. `Frando/quinn-wasm` demonstrates it compiles,
  with patches to quinn and rustls; `wasm32-unknown-unknown` lacks `Instant`
  and `SystemTime`, which a sans-I/O design lets us inject from JS. Pure npm,
  no native build.

Neither is on the critical path, because **QUIC is a prerequisite, not the
deliverable.** Above it the QUIC path additionally owes cloudflared's
`quic-pogs` stream framing and datagram-v3. The HTTP/2 path skips the QUIC
problem *and* the pogs framing: requests arrive as ordinary h2 streams that
Node already parses.

So: a transport interface with two implementations and a fallback chain,
mirroring cloudflared's own `ProtocolSelector`. HTTP/2 ships first. QUIC lands
behind the same interface without touching the public API.

The cost is real and should be documented in the TypeScript README: TCP head-
of-line blocking means measurably worse throughput under packet loss than
QUIC. That is the trade until M4.

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
          index.ts        Transport interface + protocol selector
          http2.ts        engine #1
          discovery.ts    SRV lookup
          registration.ts capnp RegistrationServer client
          roots.ts        Cloudflare origin roots, vendored PEM
        capnp/            generated from tunnelrpc.capnp
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

Mirrors cloudflared's `ProtocolSelector`: an ordered protocol list with a
fallback chain. v1 registers HTTP/2 only; the QUIC slot exists and throws
until M4.

### HTTP/2 transport

1. `dns.resolveSrv('_v2-origintunneld._tcp.argotunnel.com')`, then A/AAAA, to
   get edge addresses on port 7844.
2. `net.connect(addr, 7844)`, then `tls.connect({socket, servername:
   'h2.cftunnel.com', ALPNProtocols: ['h2']})`.
3. Run an HTTP/2 **server** over that socket. We are the server; the edge is
   the client.
4. Dispatch each stream on `Cf-Cloudflared-Proxy-Connection-Upgrade`:
   - `control-stream` — hand the stream to the capnp client and call
     `registerConnection`. The response is a union of `ConnectionError` and
     `ConnectionDetails`; success emits Connected, which satisfies the edge
     half of `tunnelReady`.
   - `websocket` — strip the header, proxy as a websocket.
   - `update-configuration` — apply and acknowledge.
   - otherwise — an ordinary request into the interceptor pipeline.
5. `reconnect()` closes the h2 session and re-dials, waiting for N Connected
   events past the pre-send count — a direct port of `edgeUpWatcher`.

### The loopback hop is kept

Go interposes a loopback reverse proxy because cloudflared needs a URL to
dial. The TypeScript transport is in-process and could call the interceptor
chain directly, but the hop is kept deliberately: the transport dials
127.0.0.1 like cloudflared does, so `InterceptCtx.target()` means precisely
what it means in Go, including its "close it to force a re-dial" lever, which
has a real mechanism behind it rather than being a preserved shape. Every
method maps 1:1 with no asterisk. The cost is one local TCP round trip per
request, which the Go engine also pays.

### Trust roots

Node ships Mozilla's bundle as `tls.rootCertificates`, so only cloudflared's
Cloudflare origin roots need vendoring as PEM in `transport/roots.ts`.

## Prototype gates

Two unknowns are load-bearing, and both are answerable in an afternoon,
independent of the rest of the library.

**G1 — HTTP/2 over a pre-established TLS socket.** Node's http2 server is
normally handed a listening socket. Feeding it an already-negotiated TLS
socket (`http2.createServer()` plus `emit('connection', socket)`) is
undocumented usage. Everything rests on it.

**G2 — Cap'n Proto RPC level 1 in JavaScript.** `capnp-es` supports it but
marks it experimental at 0.0.14. The fallback is hand-rolling the three
message encodings, which is bounded work given the interface is three methods.

If G1 fails, the native premise is dead and the experiment stops there rather
than four weeks in.

## Testing

Three tiers, mirroring the Go layout.

**Unit** — `node:test`, no test-framework dependency, matching the Go side's
zero-dep posture. Provider chain resolution order, spec envelope round-trip,
Priority auto-assignment, env-mirror precedence, `from`/`hosts` cache,
resolver.

**Cross-language conformance** — shared fixtures under `testdata/`, asserted
byte-identically by `go test` and `node:test`: spec envelopes, the
tagged-backend guard, the env-precedence table. This is what keeps the two
implementations from becoming two libraries wearing the same costume.

**Live e2e** — in `e2e/`, gated by `LIBTUNNEL_E2E_LIVE=1` as today. TypeScript
mints a real quick tunnel over HTTP/2 and fetches through it. Handoff is
tested in both directions: a Go parent mints and a TypeScript child adopts
`LIBTUNNEL_SPEC` and serves, and the reverse. That test failing is the
clearest available signal that the implementations have drifted.

## CI and release

`ci.yml` gains a Node job (node 20/22/24 across ubuntu/macos/windows)
alongside the existing Go matrix. Node floor is `>=20`.

Release stays a single tag and a single stream: the existing workflow adds an
`npm publish --provenance` step, so `Version()` and the npm package version
cannot disagree — which matters, because cross-language handoff then can never
be a version mismatch. A TypeScript-only fix burns a Go version number and
vice versa, which is acceptable at the current 0.0.x cadence.

`libtunnel` is unclaimed on npm.

## Milestones

| | Scope | Done when |
| --- | --- | --- |
| M0 | Prototype gates G1 and G2 | go/no-go on the native premise |
| M1 | discovery, transport, registration, mint | a real public URL served from pure TypeScript |
| M2 | full v1 surface | lazy getters, write-once mutators, interceptors, resolver, spec cache, handoff, env mirrors |
| M3 | TypeScript CLI, npm release wiring, conformance e2e | shippable |
| M4 | QUIC transport #2 | quinn-proto to WASM plus `node:dgram` |

M0 through M3 are one implementation plan. M4 is a separate project — a WASM
build pipeline and a QUIC polyfill are not a milestone of a tunnel library —
and gets its own spec once M3 lands.

## Risks

1. **G1.** Undocumented Node usage that the entire transport depends on.
2. **Cloudflare deprecating the `http2` protocol.** It is the UDP-blocked
   fallback, so it has a constituency, but it is the older path and this
   library would be an unusual consumer choosing it deliberately. M4 is the
   hedge.
3. **capnp-es RPC is experimental.** Bounded fallback: hand-roll three
   messages.
4. **Throughput under packet loss.** TCP head-of-line blocking versus QUIC.
   Real, measurable, and unfixable until M4 — so it belongs in the README
   rather than in someone's incident review.

## Out of scope

- Replacing or modifying any Go code. The Go module is untouched.
- A JavaScript reimplementation of the Cloudflare API beyond the quick-tunnel
  mint endpoint.
- Named tunnels, Access, WARP routing, or any cloudflared surface libtunnel
  does not already expose.
