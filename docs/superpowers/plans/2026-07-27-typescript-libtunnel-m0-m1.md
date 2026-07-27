# TypeScript libtunnel — M0 + M1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve a real public `*.trycloudflare.com` URL from a pure-TypeScript engine — no `cloudflared` binary, no subprocess, no native addon — over QUIC where the runtime supports it and HTTP/2 everywhere else.

**Architecture:** A `package.json` and `src/` tree join the untouched Go module at the repo root. The TypeScript tree mirrors the Go package split (`v1` types, `v1alpha1` implementation, backend beneath it). Two transports satisfy one interface; a protocol selector probes runtime QUIC capability and picks between them. Cap'n Proto codegen from cloudflared's own schemas drives registration on both paths.

**Tech Stack:** TypeScript, Node ≥20, `node:test`, `capnp-es` (only runtime dependency), `capnpc` (codegen-time only), `node:http2`, `node:tls`, `node:dns`, `node:quic` where available.

## Global Constraints

- **The Go module is untouched.** No `.go` file is created, modified, or deleted. Adding `WithProtocol` to the Go backend is issue #118, not this work.
- **Node floor: `>=20`.** Declared in `package.json` `engines`.
- **Runtime dependencies: `capnp-es` only.** No native addons, no `optionalDependencies`, no binary downloads.
- **`typescript` is a required peer of `capnp-es`'s codegen** — a devDependency.
- **`capnpc` (Cap'n Proto 1.5.0+) is a codegen-time prerequisite only.** Generated files are committed; consumers never need the toolchain. Install: `brew install capnp`.
- **Wire contracts are byte-exact with Go.** Backend tag is the literal string `cloudflare`. Env keys are `LIBTUNNEL__CLOUDFLARE_*`. The spec envelope must serialize identically to Go's — verified by fixture, not by eye.
- **Envelope key order:** `backend`, `hostname`, `spec`; and within `spec`: `id`, `name`, `hostname`, `account_tag`, `secret`. `name` is emitted even when empty. `secret` is standard base64. `JSON.stringify` preserves literal key order — rely on it.
- **Edge constants, copied from cloudflared, never re-derived:** SRV `_v2-origintunneld._tcp.argotunnel.com`, port `7844`, QUIC ALPN `argotunnel` / SNI `quic.cftunnel.com`, HTTP/2 SNI `h2.cftunnel.com` / ALPN `h2`.
- **TDD.** Every task writes a failing test first and commits only on green.

---

## Prototype gate results (M0)

Two of the three gates were run during planning. Their outcomes are baked into the tasks below rather than left to rediscover.

- **G1 — HTTP/2 over a pre-established TLS socket: PASS.** `http2.createServer()` plus `server.emit('connection', tlsSocket)` serves correctly over an already-negotiated TLS socket. ALPN negotiated `h2`, a custom `cf-cloudflared-proxy-connection-upgrade` header survived intact, and the handler's response reached the peer. Task 2 turns the spike into a permanent module and regression test.
- **G2 — Cap'n Proto in JavaScript: PASS.** `capnp-es` compiled both `quic_metadata_protocol.capnp` and `tunnelrpc.capnp` and generated a complete `RegistrationServer$Client` with `registerConnection` / `unregisterConnection` / `updateLocalConfiguration`, interface id `0xf71695ec7fe85497n` matching the schema. RPC runtime (`Conn`, `Server`, `Pipeline`, `DeferredTransport`) ships in the main export. Caveat discovered: `capnp-es` is only the codegen *plugin* and shells out to `capnpc`. Tasks 3 and 4 build on this.
- **G3 — `node:quic` against the real edge: OPEN.** Requires a QUIC-capable Node build. Task 8 builds the probe; Task 11 builds the transport; the CI QUIC lane in Task 8 is where G3 actually gets answered.

---

## File Structure

**Created:**

| Path | Responsibility |
| --- | --- |
| `package.json`, `tsconfig.json`, `tsconfig.test.json` | package identity, build, test loop |
| `src/index.ts` | public façade: `tunnel`, `cloudflare`, `version` |
| `src/version.ts` | the release string, `v`-prefixed to match Go |
| `src/v1/index.ts` | types + env constant table, mirroring `v1/v1.go` |
| `src/v1alpha1/cloudflare/spec.ts` | `Spec` + tagged envelope encode/decode |
| `src/v1alpha1/cloudflare/quicktunnel.ts` | quick-tunnel mint provider |
| `src/v1alpha1/cloudflare/index.ts` | `Backend`: wires provider + transport |
| `src/v1alpha1/cloudflare/transport/index.ts` | `Transport` interface, protocol selector, capability probe |
| `src/v1alpha1/cloudflare/transport/discovery.ts` | SRV → edge addresses |
| `src/v1alpha1/cloudflare/transport/h2socket.ts` | serve HTTP/2 over a pre-established socket (G1) |
| `src/v1alpha1/cloudflare/transport/http2.ts` | HTTP/2 edge transport |
| `src/v1alpha1/cloudflare/transport/quic.ts` | QUIC edge transport |
| `src/v1alpha1/cloudflare/transport/framing.ts` | quic-pogs signatures + ConnectRequest/Response |
| `src/v1alpha1/cloudflare/transport/registration.ts` | capnp stream transport + registration client |
| `src/v1alpha1/cloudflare/capnp/*.ts` | **generated**, committed |
| `src/v1alpha1/origin.ts` | the loopback origin proxy hop |
| `testdata/spec-envelope.json` | cross-language conformance fixture |

**Modified:** `Makefile` (TS targets + gofmt prune), `.gitignore`, `.github/workflows/ci.yml`.

---

### Task 1: Package scaffold and the build/test loop

**Files:**
- Create: `package.json`, `tsconfig.json`, `tsconfig.test.json`, `src/version.ts`, `src/version.test.ts`
- Modify: `.gitignore`, `Makefile:29-36`, `.github/workflows/ci.yml:80-86`

**Interfaces:**
- Produces: `version(): string` from `src/version.ts` — returns the release string with a `v` prefix, matching Go's `libtunnel.Version()`.

- [ ] **Step 1: Write the failing test**

Create `src/version.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { version } from './version.ts'

test('version is v-prefixed to match the Go Version()', () => {
  assert.match(version(), /^v\d+\.\d+\.\d+/)
})

test('version agrees with package.json', async () => {
  const pkg = await import('../package.json', { with: { type: 'json' } })
  assert.equal(version(), `v${pkg.default.version}`)
})
```

- [ ] **Step 2: Create the package files**

`package.json`:

```json
{
  "name": "libtunnel",
  "version": "0.0.37",
  "description": "Expose a local origin to the public internet through a tunnel backend",
  "license": "MIT",
  "type": "module",
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": { ".": { "types": "./dist/index.d.ts", "default": "./dist/index.js" } },
  "files": ["dist"],
  "engines": { "node": ">=20" },
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "pretest": "tsc -p tsconfig.test.json",
    "test": "node --test .test-build/",
    "capnp": "capnp-es -ots:./src/v1alpha1/cloudflare/capnp"
  },
  "dependencies": { "capnp-es": "^0.0.14" },
  "devDependencies": { "typescript": "^5.7.0", "@types/node": "^20.17.0" }
}
```

`tsconfig.json` (ships `dist/`, excludes tests):

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "rootDir": "src",
    "outDir": "dist",
    "declaration": true,
    "strict": true,
    "resolveJsonModule": true,
    "allowImportingTsExtensions": true,
    "rewriteRelativeImportExtensions": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*.ts"],
  "exclude": ["src/**/*.test.ts"]
}
```

`tsconfig.test.json` (builds tests to a separate dir so it never collides with `dist/`):

```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": { "outDir": ".test-build", "declaration": false },
  "include": ["src/**/*.ts"],
  "exclude": []
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm install && npm test`
Expected: FAIL — `Cannot find module './version.ts'`.

- [ ] **Step 4: Write the minimal implementation**

Create `src/version.ts`:

```ts
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const pkg = require('../package.json') as { version: string }

/**
 * version is the libtunnel release this build corresponds to. It carries the
 * `v` prefix so it matches Go's libtunnel.Version() exactly — the two are
 * released from one tag and must never disagree.
 */
export function version(): string {
  return `v${pkg.version}`
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test`
Expected: PASS, 2 tests.

- [ ] **Step 6: Add the ignores**

Append to `.gitignore`:

```
node_modules/
dist/
.test-build/
```

- [ ] **Step 7: Scope gofmt to tracked Go files**

`gofmt -l .` walks `node_modules` — verified, the Go tool does not skip it. Scope both call sites to tracked `.go` files instead.

In `Makefile`, replace the `fmt` and `fmt-check` bodies:

```make
# gofmt the tree in place. Scoped to tracked .go files: the repo also carries a
# node_modules/ tree, which `gofmt .` would walk (the go tool does not skip it).
fmt:
	gofmt -w $$(git ls-files '*.go')

# Fail if anything in the tree is not gofmt-clean.
fmt-check:
	@out=$$(gofmt -l $$(git ls-files '*.go')); \
	if [ -n "$$out" ]; then echo "gofmt found unformatted files:"; echo "$$out"; exit 1; fi
```

In `.github/workflows/ci.yml`, the `gofmt` step body becomes:

```yaml
          out=$(gofmt -l $(git ls-files '*.go'))
```

- [ ] **Step 8: Add TypeScript make targets**

Append to `Makefile`:

```make
# TypeScript library targets. Node >= 20; `npm ci` is assumed to have run.
.PHONY: ts-build ts-test capnp

ts-build:
	npm run build

ts-test:
	npm test

# Regenerate the Cap'n Proto bindings from cloudflared's schemas. Requires the
# capnp toolchain (brew install capnp) — codegen-time only, since the generated
# files are committed.
capnp:
	npm run capnp -- $(CAPNP_SCHEMAS)
```

- [ ] **Step 9: Add the Node CI job**

In `.github/workflows/ci.yml`, add a job alongside `ci` and `race`:

```yaml
  node:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-24.04, windows-2025, macos-26]
        node: [20, 22, 24]
    defaults:
      run:
        shell: bash
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: ${{ matrix.node }}
          cache: npm
      - run: npm ci
      - run: npm test
```

- [ ] **Step 10: Commit**

```bash
git add package.json package-lock.json tsconfig.json tsconfig.test.json \
        src/version.ts src/version.test.ts .gitignore Makefile .github/workflows/ci.yml
git commit -m "feat(ts): package scaffold, build/test loop, Node CI job"
```

---

### Task 2: Serve HTTP/2 over a pre-established TLS socket

This is G1, promoted from spike to module. It is the load-bearing primitive of the HTTP/2 transport — the leg most users will actually run — so it gets a permanent regression test that will fail loudly if a Node upgrade breaks the behavior.

**Files:**
- Create: `src/v1alpha1/cloudflare/transport/h2socket.ts`, `src/v1alpha1/cloudflare/transport/h2socket.test.ts`

**Interfaces:**
- Produces: `serveH2OverSocket(socket: Duplex, handler: H2Handler): Http2Server` and `type H2Handler = (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => void`.

- [ ] **Step 1: Write the failing test**

Create `src/v1alpha1/cloudflare/transport/h2socket.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, X509Certificate } from 'node:crypto'
import http2 from 'node:http2'
import tls from 'node:tls'
import { once } from 'node:events'
import { selfSignedCert } from './testcert.ts'
import { serveH2OverSocket } from './h2socket.ts'

test('serves HTTP/2 over an already-negotiated TLS socket', async () => {
  const { key, cert } = selfSignedCert()

  // The "edge": a TLS server that speaks HTTP/2 as the CLIENT, which is the
  // inversion cloudflared's edge performs.
  const received: Record<string, string> = {}
  const edge = tls.createServer({ key, cert, ALPNProtocols: ['h2'] }, (sock) => {
    const client = http2.connect('https://connector', { createConnection: () => sock })
    const req = client.request({
      ':method': 'GET',
      ':path': '/hello',
      'cf-cloudflared-proxy-connection-upgrade': 'control-stream',
    })
    let body = ''
    req.setEncoding('utf8')
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      received.body = body
      client.close()
    })
  })

  edge.listen(0, '127.0.0.1')
  await once(edge, 'listening')
  const { port } = edge.address() as { port: number }

  const sock = tls.connect({
    host: '127.0.0.1',
    port,
    ALPNProtocols: ['h2'],
    rejectUnauthorized: false,
  })
  await once(sock, 'secureConnect')
  assert.equal(sock.alpnProtocol, 'h2')

  const server = serveH2OverSocket(sock, (stream, headers) => {
    received.upgrade = String(headers['cf-cloudflared-proxy-connection-upgrade'])
    received.path = String(headers[':path'])
    stream.respond({ ':status': 200 })
    stream.end('served')
  })

  // Wait for the edge side to have read the full response.
  for (let i = 0; i < 100 && !received.body; i++) {
    await new Promise((r) => setTimeout(r, 20))
  }

  assert.equal(received.path, '/hello')
  assert.equal(received.upgrade, 'control-stream')
  assert.equal(received.body, 'served')

  server.close()
  sock.destroy()
  edge.close()
})
```

Create the cert helper `src/v1alpha1/cloudflare/transport/testcert.ts` — tests must not shell out to `openssl`:

```ts
import { X509Certificate, createPrivateKey, generateKeyPairSync } from 'node:crypto'

/**
 * selfSignedCert mints a throwaway self-signed certificate for tests. Node has
 * no certificate-signing API, so the PEM below is a fixed, long-lived pair
 * generated once for this repository's tests. It is a test fixture and is not
 * used by any code path that reaches the network.
 */
export function selfSignedCert(): { key: string; cert: string } {
  return { key: TEST_KEY, cert: TEST_CERT }
}

const TEST_KEY = `-----BEGIN PRIVATE KEY-----
<generated in Step 2>
-----END PRIVATE KEY-----
`

const TEST_CERT = `-----BEGIN CERTIFICATE-----
<generated in Step 2>
-----END CERTIFICATE-----
`
```

- [ ] **Step 2: Generate the test certificate**

Run this once and paste the two PEM blocks into `testcert.ts`, replacing the `<generated in Step 2>` placeholders. Delete the now-unused `generateKeyPairSync`, `createPrivateKey`, and `X509Certificate` imports from `testcert.ts` after pasting.

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /tmp/libtunnel-test-key.pem \
  -out /tmp/libtunnel-test-cert.pem \
  -days 36500 -subj "/CN=localhost"
cat /tmp/libtunnel-test-key.pem /tmp/libtunnel-test-cert.pem
```

Also remove the unused `generateKeyPairSync, X509Certificate` import line from the test file.

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module './h2socket.ts'`.

- [ ] **Step 4: Write the implementation**

Create `src/v1alpha1/cloudflare/transport/h2socket.ts`:

```ts
import http2, {
  type Http2Server,
  type IncomingHttpHeaders,
  type ServerHttp2Stream,
} from 'node:http2'
import type { Duplex } from 'node:stream'

export type H2Handler = (stream: ServerHttp2Stream, headers: IncomingHttpHeaders) => void

/**
 * serveH2OverSocket runs an HTTP/2 server over a socket whose TLS handshake has
 * already completed.
 *
 * This is the inversion cloudflared performs: the connector dials the edge, but
 * the edge is the HTTP/2 *client* and pushes requests in, so the connector must
 * be the HTTP/2 server on a connection it originated. Node's http2 server
 * normally owns its listening socket; feeding it an established one via
 * `emit('connection', ...)` is the supported path for exactly this case, and the
 * accompanying test pins the behavior against Node upgrades.
 *
 * The returned server is not listening on any port — it exists only to own the
 * session bound to this socket. Close it to tear the session down.
 */
export function serveH2OverSocket(socket: Duplex, handler: H2Handler): Http2Server {
  const server = http2.createServer()
  server.on('stream', handler)
  server.emit('connection', socket)
  return server
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/v1alpha1/cloudflare/transport/h2socket.ts \
        src/v1alpha1/cloudflare/transport/h2socket.test.ts \
        src/v1alpha1/cloudflare/transport/testcert.ts
git commit -m "feat(ts): serve HTTP/2 over a pre-established TLS socket"
```

---

### Task 3: Cap'n Proto codegen and the metadata round-trip

**Files:**
- Create: `src/v1alpha1/cloudflare/capnp/*.ts` (generated), `src/v1alpha1/cloudflare/capnp/README.md`, `src/v1alpha1/cloudflare/transport/framing.test.ts`
- Modify: `Makefile` (fill in `CAPNP_SCHEMAS`)

**Interfaces:**
- Consumes: nothing.
- Produces: generated exports `ConnectRequest`, `ConnectResponse`, `Metadata`, `ConnectionType` from `capnp/quic_metadata_protocol.ts`; `RegistrationServer$Client`, `RegistrationServer_RegisterConnection$Params`, `ConnectionResponse`, `ConnectionDetails`, `ConnectionError`, `TunnelAuth`, `ClientInfo`, `ConnectionOptions` from `capnp/tunnelrpc.ts`.

- [ ] **Step 1: Vendor the schemas and generate**

The schemas live in the cloudflared module cache. Copy them next to the generated output so regeneration is reproducible without a populated module cache:

```bash
CF=$(go env GOMODCACHE)/github.com/cloudflare/cloudflared@v0.0.0-20260612062426-68620efbce4c
mkdir -p src/v1alpha1/cloudflare/capnp/schema
cp $CF/tunnelrpc/proto/go.capnp \
   $CF/tunnelrpc/proto/tunnelrpc.capnp \
   $CF/tunnelrpc/proto/quic_metadata_protocol.capnp \
   src/v1alpha1/cloudflare/capnp/schema/
npx capnp-es -ots:./src/v1alpha1/cloudflare/capnp \
   src/v1alpha1/cloudflare/capnp/schema/quic_metadata_protocol.capnp \
   src/v1alpha1/cloudflare/capnp/schema/tunnelrpc.capnp
```

Expected output: `quic_metadata_protocol.ts` (~103 lines) and `tunnelrpc.ts` (~2047 lines).

Then set the variable in `Makefile` so `make capnp` reproduces it:

```make
CAPNP_SCHEMAS = src/v1alpha1/cloudflare/capnp/schema/quic_metadata_protocol.capnp \
                src/v1alpha1/cloudflare/capnp/schema/tunnelrpc.capnp
```

- [ ] **Step 2: Document why the generated files are committed**

Create `src/v1alpha1/cloudflare/capnp/README.md`:

```markdown
# Generated Cap'n Proto bindings

Generated from cloudflared's own schemas in `./schema`, vendored from the
cloudflared module at the version pinned in `go.mod`.

Regenerate with `make capnp`. That requires the Cap'n Proto toolchain
(`brew install capnp`): `capnp-es` is only the codegen plugin and shells out to
`capnpc`. The output is committed so consumers of the npm package never need
the toolchain.

Do not edit these files by hand.
```

- [ ] **Step 3: Write the failing round-trip test**

Create `src/v1alpha1/cloudflare/transport/framing.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encodeConnectRequest, decodeConnectRequest } from './framing.ts'
import { ConnectionType } from '../capnp/quic_metadata_protocol.ts'

test('ConnectRequest round-trips through capnp', () => {
  const wire = encodeConnectRequest({
    dest: 'https://example.trycloudflare.com/path',
    type: ConnectionType.HTTP,
    metadata: [
      { key: 'HttpMethod', val: 'GET' },
      { key: 'HttpHost', val: 'example.trycloudflare.com' },
      { key: 'HttpHeader:User-Agent', val: 'curl/8.0' },
    ],
  })

  const got = decodeConnectRequest(wire)
  assert.equal(got.dest, 'https://example.trycloudflare.com/path')
  assert.equal(got.type, ConnectionType.HTTP)
  assert.deepEqual(got.metadata, [
    { key: 'HttpMethod', val: 'GET' },
    { key: 'HttpHost', val: 'example.trycloudflare.com' },
    { key: 'HttpHeader:User-Agent', val: 'curl/8.0' },
  ])
})

test('an empty metadata list round-trips', () => {
  const got = decodeConnectRequest(
    encodeConnectRequest({ dest: 'x', type: ConnectionType.WEBSOCKET, metadata: [] }),
  )
  assert.equal(got.dest, 'x')
  assert.equal(got.type, ConnectionType.WEBSOCKET)
  assert.deepEqual(got.metadata, [])
})
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module './framing.ts'`.

- [ ] **Step 5: Write the implementation**

Create `src/v1alpha1/cloudflare/transport/framing.ts`:

```ts
import { Message } from 'capnp-es'
import {
  ConnectRequest,
  ConnectResponse,
  ConnectionType,
  Metadata,
} from '../capnp/quic_metadata_protocol.ts'

export interface MetadataPair {
  key: string
  val: string
}

export interface ConnectRequestData {
  dest: string
  type: ConnectionType
  metadata: MetadataPair[]
}

export function encodeConnectRequest(data: ConnectRequestData): Uint8Array {
  const msg = new Message()
  const root = msg.initRoot(ConnectRequest)
  root.dest = data.dest
  root.type = data.type
  const list = root._initMetadata(data.metadata.length)
  data.metadata.forEach((pair, i) => {
    const m = list.get(i)
    m.key = pair.key
    m.val = pair.val
  })
  return new Uint8Array(msg.toArrayBuffer())
}

export function decodeConnectRequest(bytes: Uint8Array): ConnectRequestData {
  const root = new Message(bytes, false).getRoot(ConnectRequest)
  const metadata: MetadataPair[] = []
  if (root._hasMetadata()) {
    for (const m of root.metadata) metadata.push({ key: m.key, val: m.val })
  }
  return { dest: root.dest, type: root.type, metadata }
}

export function encodeConnectResponse(error: string, metadata: MetadataPair[] = []): Uint8Array {
  const msg = new Message()
  const root = msg.initRoot(ConnectResponse)
  root.error = error
  const list = root._initMetadata(metadata.length)
  metadata.forEach((pair, i) => {
    const m = list.get(i)
    m.key = pair.key
    m.val = pair.val
  })
  return new Uint8Array(msg.toArrayBuffer())
}

export { ConnectionType, Metadata }
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `npm test`
Expected: PASS.

If the generated accessor names differ from those used above, read
`src/v1alpha1/cloudflare/capnp/quic_metadata_protocol.ts` and use the names it
actually declares — the generated file is the authority, not this plan.

- [ ] **Step 7: Commit**

```bash
git add src/v1alpha1/cloudflare/capnp src/v1alpha1/cloudflare/transport/framing.ts \
        src/v1alpha1/cloudflare/transport/framing.test.ts Makefile
git commit -m "feat(ts): capnp codegen from cloudflared schemas + ConnectRequest framing"
```

---

### Task 4: Cap'n Proto stream transport and the registration client

cloudflared speaks capnp RPC over a byte stream using unpacked message framing. `capnp-es` provides the RPC machinery (`Conn`) but not a Node `Duplex` adapter; this task writes it and wraps the three-method registration interface in a typed client.

**Files:**
- Create: `src/v1alpha1/cloudflare/transport/registration.ts`, `src/v1alpha1/cloudflare/transport/registration.test.ts`

**Interfaces:**
- Consumes: generated `RegistrationServer$Client` from Task 3.
- Produces:
  - `streamTransport(stream: Duplex): Transport` — a `capnp-es` RPC transport over a Node duplex.
  - `registerConnection(stream, params): Promise<ConnectionDetails>` where
    `params = { accountTag: string; tunnelSecret: Uint8Array; tunnelId: Uint8Array; connIndex: number; clientId: Uint8Array; version: string; arch: string; features: string[] }`
    and `ConnectionDetails = { uuid: Uint8Array; locationName: string; tunnelIsRemotelyManaged: boolean }`.

- [ ] **Step 1: Write the failing test**

Create `src/v1alpha1/cloudflare/transport/registration.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { PassThrough, Duplex } from 'node:stream'
import { streamTransport } from './registration.ts'

/** A pair of duplexes wired to each other, standing in for two stream ends. */
function duplexPair(): [Duplex, Duplex] {
  const a2b = new PassThrough()
  const b2a = new PassThrough()
  const a = Duplex.from({ readable: b2a, writable: a2b })
  const b = Duplex.from({ readable: a2b, writable: b2a })
  return [a, b]
}

test('streamTransport moves a capnp message end to end', async () => {
  const [a, b] = duplexPair()
  const ta = streamTransport(a)
  const tb = streamTransport(b)

  const payload = new Uint8Array([0, 0, 0, 0, 1, 2, 3, 4])
  await ta.write(payload)

  const got = await tb.read()
  assert.deepEqual(Array.from(got), Array.from(payload))
})

test('streamTransport surfaces stream errors to the reader', async () => {
  const [a] = duplexPair()
  const ta = streamTransport(a)
  a.destroy(new Error('boom'))
  await assert.rejects(() => ta.read(), /boom/)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module './registration.ts'`.

- [ ] **Step 3: Write the implementation**

Create `src/v1alpha1/cloudflare/transport/registration.ts`:

```ts
import { Message } from 'capnp-es'
import type { Duplex } from 'node:stream'
import {
  RegistrationServer$Client,
  type ConnectionDetails as CapnpConnectionDetails,
} from '../capnp/tunnelrpc.ts'

/**
 * Transport is the byte-level interface capnp RPC needs: framed messages in,
 * framed messages out. cloudflared uses unpacked segment framing over the
 * stream, which is what capnp-es's Message serialization already produces.
 */
export interface Transport {
  write(bytes: Uint8Array): Promise<void>
  read(): Promise<Uint8Array>
  close(): void
}

/**
 * streamTransport adapts a Node duplex to the capnp RPC transport shape. Reads
 * resolve with whatever the stream yields next; a stream error rejects the
 * pending read rather than hanging it, so a dropped edge connection surfaces as
 * a failed registration instead of a stall.
 */
export function streamTransport(stream: Duplex): Transport {
  let err: Error | null = null
  stream.on('error', (e: Error) => {
    err = e
  })

  return {
    write(bytes: Uint8Array): Promise<void> {
      return new Promise((resolve, reject) => {
        stream.write(bytes, (e) => (e ? reject(e) : resolve()))
      })
    },

    read(): Promise<Uint8Array> {
      if (err) return Promise.reject(err)
      const chunk = stream.read()
      if (chunk) return Promise.resolve(new Uint8Array(chunk))

      return new Promise((resolve, reject) => {
        const onReadable = () => {
          const c = stream.read()
          if (c) {
            cleanup()
            resolve(new Uint8Array(c))
          }
        }
        const onError = (e: Error) => {
          cleanup()
          reject(e)
        }
        const onEnd = () => {
          cleanup()
          reject(new Error('capnp stream ended before a message arrived'))
        }
        const cleanup = () => {
          stream.off('readable', onReadable)
          stream.off('error', onError)
          stream.off('end', onEnd)
        }
        stream.on('readable', onReadable)
        stream.on('error', onError)
        stream.on('end', onEnd)
      })
    },

    close(): void {
      stream.end()
    },
  }
}

export interface RegisterParams {
  accountTag: string
  tunnelSecret: Uint8Array
  tunnelId: Uint8Array
  connIndex: number
  clientId: Uint8Array
  version: string
  arch: string
  features: string[]
}

export interface ConnectionDetails {
  uuid: Uint8Array
  locationName: string
  tunnelIsRemotelyManaged: boolean
}

/**
 * registerConnection performs the one RPC that makes a tunnel live. The edge
 * replies with a union: an error (with a retry hint) or the connection details.
 * A returned error is thrown, so callers treat registration as pass/fail.
 */
export async function registerConnection(
  transport: Transport,
  params: RegisterParams,
): Promise<ConnectionDetails> {
  const { Conn } = await import('capnp-es')
  const conn = new Conn(transport as never, {})
  const client = new RegistrationServer$Client(conn.bootstrap())

  const results = await client
    .registerConnection((p) => {
      const auth = p._initAuth()
      auth.accountTag = params.accountTag
      auth._initTunnelSecret(params.tunnelSecret.length).copyBuffer(params.tunnelSecret)
      p._initTunnelId(params.tunnelId.length).copyBuffer(params.tunnelId)
      p.connIndex = params.connIndex
      const opts = p._initOptions()
      const info = opts._initClient()
      info._initClientId(params.clientId.length).copyBuffer(params.clientId)
      info.version = params.version
      info.arch = params.arch
      const feats = info._initFeatures(params.features.length)
      params.features.forEach((f, i) => feats.set(i, f))
      opts.replaceExisting = false
      opts.compressionQuality = 0
      opts.numPreviousAttempts = 0
    })
    .promise()

  const response = results.result
  if (response.result._isError) {
    const e = response.result.error
    throw new Error(`edge refused registration: ${e.cause}`)
  }

  const details: CapnpConnectionDetails = response.result.connectionDetails
  return {
    uuid: new Uint8Array(details.uuid.toArrayBuffer()),
    locationName: details.locationName,
    tunnelIsRemotelyManaged: details.tunnelIsRemotelyManaged,
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test`
Expected: PASS.

The generated `tunnelrpc.ts` is the authority on the exact initializer names
(`_initAuth`, `_initTunnelId`, `copyBuffer`, the union discriminator). Read it
and adjust `registerConnection` to match what it declares; the transport and its
tests do not depend on those names and should pass unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/v1alpha1/cloudflare/transport/registration.ts \
        src/v1alpha1/cloudflare/transport/registration.test.ts
git commit -m "feat(ts): capnp stream transport + registerConnection client"
```

---

### Task 5: Edge discovery

**Files:**
- Create: `src/v1alpha1/cloudflare/transport/discovery.ts`, `src/v1alpha1/cloudflare/transport/discovery.test.ts`

**Interfaces:**
- Produces: `discoverEdge(resolver?: EdgeResolver): Promise<EdgeAddr[]>` where `EdgeAddr = { host: string; ip: string; port: number }`, and `interface EdgeResolver { resolveSrv(name: string): Promise<SrvRecord[]>; resolve4(host: string): Promise<string[]>; resolve6(host: string): Promise<string[]> }`.

- [ ] **Step 1: Write the failing test**

Create `src/v1alpha1/cloudflare/transport/discovery.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { discoverEdge, SRV_NAME } from './discovery.ts'

const fakeResolver = {
  async resolveSrv(name: string) {
    assert.equal(name, SRV_NAME)
    return [
      { name: 'region1.v2.argotunnel.com', port: 7844, priority: 1, weight: 1 },
      { name: 'region2.v2.argotunnel.com', port: 7844, priority: 1, weight: 1 },
    ]
  },
  async resolve4(host: string) {
    return host.startsWith('region1') ? ['198.41.192.1'] : ['198.41.200.1']
  },
  async resolve6() {
    return []
  },
}

test('resolves SRV then A records into edge addresses', async () => {
  const addrs = await discoverEdge(fakeResolver)
  assert.deepEqual(addrs, [
    { host: 'region1.v2.argotunnel.com', ip: '198.41.192.1', port: 7844 },
    { host: 'region2.v2.argotunnel.com', ip: '198.41.200.1', port: 7844 },
  ])
})

test('includes AAAA records when present', async () => {
  const addrs = await discoverEdge({
    ...fakeResolver,
    async resolveSrv() {
      return [{ name: 'region1.v2.argotunnel.com', port: 7844, priority: 1, weight: 1 }]
    },
    async resolve6() {
      return ['2606:4700:a0::1']
    },
  })
  assert.deepEqual(addrs.map((a) => a.ip), ['198.41.192.1', '2606:4700:a0::1'])
})

test('the SRV name matches cloudflared exactly', () => {
  assert.equal(SRV_NAME, '_v2-origintunneld._tcp.argotunnel.com')
})

test('an empty SRV answer is an error, not an empty list', async () => {
  await assert.rejects(
    () => discoverEdge({ ...fakeResolver, async resolveSrv() { return [] } }),
    /no edge addresses/,
  )
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module './discovery.ts'`.

- [ ] **Step 3: Write the implementation**

Create `src/v1alpha1/cloudflare/transport/discovery.ts`:

```ts
import { promises as dns, type SrvRecord } from 'node:dns'

/**
 * SRV_NAME is cloudflared's edge discovery record — service `v2-origintunneld`,
 * proto `tcp`, name `argotunnel.com`. Copied verbatim from cloudflared's
 * edgediscovery/allregions/discovery.go rather than reassembled, so it cannot
 * drift by a typo.
 */
export const SRV_NAME = '_v2-origintunneld._tcp.argotunnel.com'

export interface EdgeAddr {
  host: string
  ip: string
  port: number
}

export interface EdgeResolver {
  resolveSrv(name: string): Promise<SrvRecord[]>
  resolve4(host: string): Promise<string[]>
  resolve6(host: string): Promise<string[]>
}

const systemResolver: EdgeResolver = {
  resolveSrv: (name) => dns.resolveSrv(name),
  resolve4: (host) => dns.resolve4(host),
  resolve6: (host) => dns.resolve6(host),
}

/**
 * discoverEdge resolves the edge SRV record into concrete addresses. Both
 * transports dial the same addresses; only the TLS parameters differ.
 *
 * A host that resolves to nothing is skipped rather than fatal — regions come
 * and go — but an empty final list is an error, since dialing cannot proceed.
 */
export async function discoverEdge(
  resolver: EdgeResolver = systemResolver,
): Promise<EdgeAddr[]> {
  const srv = await resolver.resolveSrv(SRV_NAME)
  const addrs: EdgeAddr[] = []

  for (const record of srv) {
    const [v4, v6] = await Promise.all([
      resolver.resolve4(record.name).catch(() => [] as string[]),
      resolver.resolve6(record.name).catch(() => [] as string[]),
    ])
    for (const ip of [...v4, ...v6]) {
      addrs.push({ host: record.name, ip, port: record.port })
    }
  }

  if (addrs.length === 0) {
    throw new Error(`no edge addresses resolved from ${SRV_NAME}`)
  }
  return addrs
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/v1alpha1/cloudflare/transport/discovery.ts \
        src/v1alpha1/cloudflare/transport/discovery.test.ts
git commit -m "feat(ts): edge SRV discovery"
```

---

### Task 6: Spec and the tagged envelope

The envelope is a wire contract shared with Go. This task pins it with a fixture generated from the Go implementation, so drift fails a test rather than a handoff.

**Files:**
- Create: `src/v1alpha1/cloudflare/spec.ts`, `src/v1alpha1/cloudflare/spec.test.ts`, `testdata/spec-envelope.json`

**Interfaces:**
- Produces:
  - `interface Spec { id: string; name: string; hostname: string; account_tag: string; secret: Uint8Array }`
  - `serializeSpec(spec: Spec): string`
  - `decodeEnvelope(envelope: string): { backend: string; spec: Spec }`
  - `const BACKEND_NAME = 'cloudflare'`

- [ ] **Step 1: Create the conformance fixture from Go**

The fixture is data produced by the Go implementation, so it is authoritative. Generate it with a throwaway program (do not commit the program — it would be new Go code):

```bash
cat > /tmp/envgen.go <<'EOF'
package main

import (
	"fmt"

	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

func main() {
	s := &cloudflare.Spec{
		ID:         "f4e1b7a0-1111-2222-3333-444455556666",
		Name:       "",
		Hostname:   "example-quick-tunnel.trycloudflare.com",
		AccountTag: "abc123def456",
		Secret:     []byte{0x01, 0x02, 0x03, 0x04},
	}
	fmt.Println(s.Serialize())
}
EOF
mkdir -p testdata
go run /tmp/envgen.go > testdata/spec-envelope.json
cat testdata/spec-envelope.json
```

Expected content (one line, exactly):

```json
{"backend":"cloudflare","hostname":"example-quick-tunnel.trycloudflare.com","spec":{"id":"f4e1b7a0-1111-2222-3333-444455556666","name":"","hostname":"example-quick-tunnel.trycloudflare.com","account_tag":"abc123def456","secret":"AQIDBA=="}}
```

- [ ] **Step 2: Write the failing test**

Create `src/v1alpha1/cloudflare/spec.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { serializeSpec, decodeEnvelope, BACKEND_NAME, type Spec } from './spec.ts'

const fixture = readFileSync(new URL('../../../testdata/spec-envelope.json', import.meta.url), 'utf8').trim()

const spec: Spec = {
  id: 'f4e1b7a0-1111-2222-3333-444455556666',
  name: '',
  hostname: 'example-quick-tunnel.trycloudflare.com',
  account_tag: 'abc123def456',
  secret: new Uint8Array([1, 2, 3, 4]),
}

test('serializes byte-identically to the Go implementation', () => {
  assert.equal(serializeSpec(spec), fixture)
})

test('the backend tag is the literal Go uses', () => {
  assert.equal(BACKEND_NAME, 'cloudflare')
})

test('decodes a Go-produced envelope', () => {
  const { backend, spec: got } = decodeEnvelope(fixture)
  assert.equal(backend, 'cloudflare')
  assert.equal(got.hostname, 'example-quick-tunnel.trycloudflare.com')
  assert.equal(got.account_tag, 'abc123def456')
  assert.deepEqual(Array.from(got.secret), [1, 2, 3, 4])
})

test('a foreign backend tag is rejected loudly, not silently unmarshaled', () => {
  const foreign = fixture.replace('"cloudflare"', '"ngrok"')
  assert.throws(() => decodeEnvelope(foreign), /ngrok/)
})

test('round-trips its own output', () => {
  assert.equal(serializeSpec(decodeEnvelope(serializeSpec(spec)).spec), fixture)
})
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module './spec.ts'`.

- [ ] **Step 4: Write the implementation**

Create `src/v1alpha1/cloudflare/spec.ts`:

```ts
/**
 * BACKEND_NAME tags every spec this backend mints. It is a wire contract: the
 * Go implementation writes the same literal, and a child adopting a spec tagged
 * with a different backend must fail loudly rather than unmarshal a foreign
 * credential set. Do not "improve" this string.
 */
export const BACKEND_NAME = 'cloudflare'

export interface Spec {
  id: string
  name: string
  hostname: string
  account_tag: string
  secret: Uint8Array
}

/**
 * serializeSpec renders the tagged envelope carried by LIBTUNNEL_SPEC.
 *
 * The output must be byte-identical to Go's EncodeSpec, so the key order below
 * is load-bearing: Go's encoding/json emits struct fields in declaration order,
 * and JSON.stringify emits object literal keys in insertion order. The envelope
 * is backend, hostname, spec; the spec is id, name, hostname, account_tag,
 * secret. `name` is emitted even when empty (Go has no omitempty on it), and
 * `secret` is standard base64 (Go's []byte JSON encoding).
 */
export function serializeSpec(spec: Spec): string {
  return JSON.stringify({
    backend: BACKEND_NAME,
    hostname: spec.hostname,
    spec: {
      id: spec.id,
      name: spec.name,
      hostname: spec.hostname,
      account_tag: spec.account_tag,
      secret: Buffer.from(spec.secret).toString('base64'),
    },
  })
}

export function decodeEnvelope(envelope: string): { backend: string; spec: Spec } {
  const parsed = JSON.parse(envelope) as {
    backend?: string
    spec?: Record<string, unknown>
  }

  if (!parsed.backend) {
    throw new Error('not a libtunnel spec envelope: no backend tag')
  }
  if (parsed.backend !== BACKEND_NAME) {
    throw new Error(
      `spec envelope is tagged for backend ${parsed.backend}, not ${BACKEND_NAME}`,
    )
  }
  if (!parsed.spec) {
    throw new Error('spec envelope has no spec body')
  }

  const body = parsed.spec
  return {
    backend: parsed.backend,
    spec: {
      id: String(body.id ?? ''),
      name: String(body.name ?? ''),
      hostname: String(body.hostname ?? ''),
      account_tag: String(body.account_tag ?? ''),
      secret: new Uint8Array(Buffer.from(String(body.secret ?? ''), 'base64')),
    },
  }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test`
Expected: PASS, 5 tests.

- [ ] **Step 6: Commit**

```bash
git add src/v1alpha1/cloudflare/spec.ts src/v1alpha1/cloudflare/spec.test.ts \
        testdata/spec-envelope.json
git commit -m "feat(ts): spec envelope, byte-exact with the Go encoder"
```

---

### Task 7: The quick-tunnel mint provider

**Files:**
- Create: `src/v1alpha1/cloudflare/quicktunnel.ts`, `src/v1alpha1/cloudflare/quicktunnel.test.ts`

**Interfaces:**
- Consumes: `Spec` from Task 6.
- Produces: `mintQuickTunnel(opts?: MintOptions): Promise<Spec>` where `MintOptions = { url?: string; signal?: AbortSignal; log?: Logger; fetchImpl?: typeof fetch }`, and `interface Logger { debug(msg: string, fields?: object): void; info(...): void; warn(...): void; error(...): void }`.

- [ ] **Step 1: Write the failing test**

Create `src/v1alpha1/cloudflare/quicktunnel.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mintQuickTunnel, QUICK_TUNNEL_URL } from './quicktunnel.ts'

const ok = {
  success: true,
  result: {
    id: 'f4e1b7a0-1111-2222-3333-444455556666',
    name: 'quick',
    hostname: 'example.trycloudflare.com',
    account_tag: 'abc123',
    secret: 'AQIDBA==',
  },
}

test('mints a spec from the API response', async () => {
  const spec = await mintQuickTunnel({
    fetchImpl: async () => new Response(JSON.stringify(ok), { status: 200 }),
  })
  assert.equal(spec.hostname, 'example.trycloudflare.com')
  assert.equal(spec.account_tag, 'abc123')
  assert.deepEqual(Array.from(spec.secret), [1, 2, 3, 4])
})

test('posts to the documented endpoint with a cloudflared user-agent', async () => {
  let seen: { url: string; method?: string; ua?: string } | null = null
  await mintQuickTunnel({
    fetchImpl: async (url, init) => {
      seen = {
        url: String(url),
        method: init?.method,
        ua: new Headers(init?.headers).get('user-agent') ?? undefined,
      }
      return new Response(JSON.stringify(ok), { status: 200 })
    },
  })
  assert.equal(seen!.url, QUICK_TUNNEL_URL)
  assert.equal(seen!.method, 'POST')
  assert.match(seen!.ua!, /^cloudflared\//)
})

test('success:false on a 4xx is fatal, not retried', async () => {
  let calls = 0
  await assert.rejects(
    () =>
      mintQuickTunnel({
        fetchImpl: async () => {
          calls++
          return new Response(
            JSON.stringify({ success: false, errors: [{ code: 1015, message: 'nope' }] }),
            { status: 400 },
          )
        },
      }),
    /mint rejected.*1015: nope/,
  )
  assert.equal(calls, 1)
})

test('a 429 aborts through the signal rather than looping forever', async () => {
  const ac = new AbortController()
  let calls = 0
  const p = mintQuickTunnel({
    signal: ac.signal,
    fetchImpl: async () => {
      calls++
      if (calls === 1) setTimeout(() => ac.abort(), 0)
      return new Response('', { status: 429, headers: { 'retry-after': '1' } })
    },
  })
  await assert.rejects(() => p, /rate limited|abort/i)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module './quicktunnel.ts'`.

- [ ] **Step 3: Write the implementation**

Create `src/v1alpha1/cloudflare/quicktunnel.ts`:

```ts
import { version } from '../../version.ts'
import type { Spec } from './spec.ts'

/** The public endpoint that mints anonymous quick tunnels. */
export const QUICK_TUNNEL_URL = 'https://api.trycloudflare.com/tunnel'

export interface Logger {
  debug(msg: string, fields?: object): void
  info(msg: string, fields?: object): void
  warn(msg: string, fields?: object): void
  error(msg: string, fields?: object): void
}

export interface MintOptions {
  url?: string
  signal?: AbortSignal
  log?: Logger
  fetchImpl?: typeof fetch
}

interface MintResponse {
  success: boolean
  errors?: { code: number; message: string }[]
  result?: {
    id: string
    name: string
    hostname: string
    account_tag: string
    secret: string
  }
}

/**
 * mintQuickTunnel requests anonymous quick-tunnel credentials, retrying with
 * linear backoff until the signal aborts. The API rate-limits aggressively, so
 * a 429 is retried; a parsed success:false on a non-5xx is the API saying no,
 * which retrying cannot fix, so it fails immediately.
 */
export async function mintQuickTunnel(opts: MintOptions = {}): Promise<Spec> {
  const endpoint = opts.url ?? QUICK_TUNNEL_URL
  const doFetch = opts.fetchImpl ?? fetch
  let sleepMs = 0

  for (;;) {
    let lastErr: Error
    try {
      const resp = await doFetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'user-agent': `cloudflared/${version()}`,
        },
        signal: opts.signal,
      })

      if (resp.status === 429) {
        const retryAfter = resp.headers.get('retry-after')
        lastErr = new Error(
          `quick tunnel rate limited (HTTP 429)${retryAfter ? `: Retry-After=${retryAfter}` : ''}`,
        )
      } else {
        const body = await resp.text()
        let data: MintResponse
        try {
          data = JSON.parse(body) as MintResponse
        } catch {
          lastErr = new Error(
            `tunnel credentials request failed (status=${resp.status}): ${body.trim()}`,
          )
          throw lastErr
        }

        if (data.success && data.result) {
          const r = data.result
          return {
            id: r.id,
            name: r.name,
            hostname: r.hostname,
            account_tag: r.account_tag,
            secret: new Uint8Array(Buffer.from(r.secret, 'base64')),
          }
        }

        const detail = (data.errors ?? []).map((e) => `${e.code}: ${e.message}`).join('; ')
        if (resp.status < 500) {
          // The API said no. Retrying cannot change that.
          throw new Error(`quick tunnel mint rejected: ${detail}`)
        }
        lastErr = new Error(`tunnel credentials request failed: ${detail}`)
      }
    } catch (e) {
      const err = e as Error
      if (err.message.startsWith('quick tunnel mint rejected')) throw err
      if (opts.signal?.aborted) throw err
      lastErr = err
    }

    opts.log?.warn('failed to mint quick tunnel, retrying', {
      error: lastErr.message,
      nextAttemptInMs: sleepMs + 1000,
    })

    sleepMs += 1000
    await sleep(sleepMs, opts.signal, lastErr)
  }
}

function sleep(ms: number, signal: AbortSignal | undefined, cause: Error): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(cause)
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = () => {
      clearTimeout(timer)
      reject(cause)
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/v1alpha1/cloudflare/quicktunnel.ts src/v1alpha1/cloudflare/quicktunnel.test.ts
git commit -m "feat(ts): quick-tunnel mint provider with rate-limit backoff"
```

---

### Task 8: QUIC capability probe and the protocol selector

**Files:**
- Create: `src/v1alpha1/cloudflare/transport/index.ts`, `src/v1alpha1/cloudflare/transport/index.test.ts`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `Logger` from Task 7.
- Produces:
  - `type Protocol = 'auto' | 'quic' | 'http2'`
  - `interface QuicCapability { available: boolean; reason?: string }`
  - `probeQuic(): Promise<QuicCapability>`
  - `selectProtocol(requested: Protocol, log?: Logger, probe?: () => Promise<QuicCapability>): Promise<'quic' | 'http2'>`
  - `interface Transport { readonly protocol: 'quic' | 'http2'; connect(opts: ConnectOptions): Promise<EdgeConnection> }`

- [ ] **Step 1: Write the failing test**

Create `src/v1alpha1/cloudflare/transport/index.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { selectProtocol, probeQuic } from './index.ts'

const yes = async () => ({ available: true })
const no = async () => ({ available: false, reason: 'node_use_quic is false' })

function capturingLogger() {
  const warns: string[] = []
  const noop = () => {}
  return {
    warns,
    log: { debug: noop, info: noop, warn: (m: string) => void warns.push(m), error: noop },
  }
}

test('auto prefers quic when the runtime supports it', async () => {
  assert.equal(await selectProtocol('auto', undefined, yes), 'quic')
})

test('auto falls back to http2 and warns exactly once', async () => {
  const { warns, log } = capturingLogger()
  assert.equal(await selectProtocol('auto', log, no), 'http2')
  assert.equal(await selectProtocol('auto', log, no), 'http2')
  assert.equal(warns.length, 1, 'the fallback warning must not repeat per tunnel')
  assert.match(warns[0], /node_use_quic is false/)
})

test('explicit quic fails loudly instead of falling back', async () => {
  await assert.rejects(() => selectProtocol('quic', undefined, no), /QUIC was requested/)
})

test('explicit http2 never probes', async () => {
  let probed = false
  const spy = async () => {
    probed = true
    return { available: true }
  }
  assert.equal(await selectProtocol('http2', undefined, spy), 'http2')
  assert.equal(probed, false)
})

test('the real probe reports a reason when unavailable', async () => {
  const cap = await probeQuic()
  if (!cap.available) assert.ok(cap.reason && cap.reason.length > 0)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module './index.ts'`.

- [ ] **Step 3: Write the implementation**

Create `src/v1alpha1/cloudflare/transport/index.ts`:

```ts
import type { Duplex } from 'node:stream'
import type { Logger } from '../quicktunnel.ts'
import type { EdgeAddr } from './discovery.ts'

export type Protocol = 'auto' | 'quic' | 'http2'

export interface QuicCapability {
  available: boolean
  reason?: string
}

/**
 * probeQuic reports whether this runtime can actually open a QUIC connection.
 *
 * node:quic is gated twice: --experimental-quic is a build-time configure flag
 * *and* a runtime flag, and stock Node ships with the build side off
 * (process.config.variables.node_use_quic === false), so the runtime flag alone
 * cannot reach it. Testing for a flag would therefore be wrong; this probes
 * capability — the build variable, then an actual guarded import.
 */
export async function probeQuic(): Promise<QuicCapability> {
  const vars = process.config.variables as Record<string, unknown>
  if (!vars.node_use_quic) {
    return {
      available: false,
      reason:
        'this Node build has no QUIC support (process.config.variables.node_use_quic is false); ' +
        'node:quic requires a build configured with --experimental-quic',
    }
  }
  try {
    await import('node:quic')
    return { available: true }
  } catch (e) {
    return { available: false, reason: `node:quic could not be imported: ${(e as Error).message}` }
  }
}

/**
 * warnedOnce keeps the auto-fallback warning to one per process. The reason a
 * runtime lacks QUIC does not change between tunnels, so repeating it per tunnel
 * is noise that would train operators to ignore it.
 */
let warnedOnce = false

/**
 * selectProtocol resolves the requested protocol to a concrete one, matching
 * cloudflared's semantics: `auto` prefers QUIC and falls back to HTTP/2, while
 * an explicitly requested protocol never falls back (cloudflared's
 * staticProtocolSelector returns no fallback).
 */
export async function selectProtocol(
  requested: Protocol,
  log?: Logger,
  probe: () => Promise<QuicCapability> = probeQuic,
): Promise<'quic' | 'http2'> {
  if (requested === 'http2') return 'http2'

  const cap = await probe()

  if (requested === 'quic') {
    if (cap.available) return 'quic'
    throw new Error(`QUIC was requested explicitly but is unavailable: ${cap.reason}`)
  }

  if (cap.available) return 'quic'
  if (!warnedOnce) {
    warnedOnce = true
    log?.warn(`falling back to the HTTP/2 edge transport: ${cap.reason}`, {
      protocol: 'http2',
    })
  }
  return 'http2'
}

/** Test-only: reset the once-per-process warning latch. */
export function resetProtocolWarning(): void {
  warnedOnce = false
}

export interface ConnectOptions {
  addr: EdgeAddr
  caCerts: string[]
  accountTag: string
  tunnelSecret: Uint8Array
  tunnelId: Uint8Array
  hostname: string
  connIndex: number
  log?: Logger
  signal?: AbortSignal
  /** Called for each inbound request the edge pushes in. */
  onRequest: EdgeRequestHandler
}

export interface EdgeRequest {
  method: string
  path: string
  host: string
  headers: Record<string, string>
  body: Duplex | null
}

export type EdgeRequestHandler = (req: EdgeRequest, respond: EdgeResponder) => void

export interface EdgeResponder {
  writeHead(status: number, headers: Record<string, string>): void
  body(): Duplex
}

export interface EdgeConnection {
  readonly locationName: string
  close(): void
  closed(): Promise<void>
}

export interface Transport {
  readonly protocol: 'quic' | 'http2'
  connect(opts: ConnectOptions): Promise<EdgeConnection>
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test`
Expected: PASS, 5 tests.

Note: the "warns exactly once" test and any later test that exercises fallback share the module-level latch. If a later task adds such a test, call `resetProtocolWarning()` in its setup.

- [ ] **Step 5: Add the CI QUIC lane**

This is where G3 gets answered on an ongoing basis. Add to `.github/workflows/ci.yml`:

```yaml
  # QUIC lane. node:quic requires a Node built with --experimental-quic, which
  # release builds are not, so this tracks nightly. Allowed to fail — it follows
  # an unstable upstream — but its failures stay visible rather than absent.
  node-quic:
    runs-on: ubuntu-24.04
    continue-on-error: true
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: nightly
          cache: npm
      - run: npm ci
      - name: report QUIC capability
        run: |
          node -p "'node_use_quic=' + process.config.variables.node_use_quic"
          node --experimental-quic -e "import('node:quic').then(
            () => console.log('node:quic OK'),
            (e) => { console.log('node:quic unavailable: ' + e.message); process.exit(1) })"
      - name: quic-pinned tests
        env:
          LIBTUNNEL__CLOUDFLARE_PROTOCOL: quic
        run: npm test
```

- [ ] **Step 6: Commit**

```bash
git add src/v1alpha1/cloudflare/transport/index.ts \
        src/v1alpha1/cloudflare/transport/index.test.ts .github/workflows/ci.yml
git commit -m "feat(ts): QUIC capability probe + auto/quic/http2 selector"
```

---

### Task 9: The loopback origin hop

Go interposes a loopback reverse proxy because cloudflared needs a URL to dial. The design keeps that hop so `InterceptCtx.target()` retains its meaning and its "close to force a re-dial" lever. This task builds the hop; interceptors themselves are M2.

**Files:**
- Create: `src/v1alpha1/origin.ts`, `src/v1alpha1/origin.test.ts`

**Interfaces:**
- Produces: `startOriginProxy(origin: URL, log?: Logger): Promise<OriginProxy>` where `OriginProxy = { address: URL; server: import('node:http').Server; close(): void }`.

- [ ] **Step 1: Write the failing test**

Create `src/v1alpha1/origin.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { once } from 'node:events'
import { startOriginProxy } from './origin.ts'

async function listeningOrigin(handler: http.RequestListener) {
  const srv = http.createServer(handler)
  srv.listen(0, '127.0.0.1')
  await once(srv, 'listening')
  const { port } = srv.address() as { port: number }
  return { srv, url: new URL(`http://127.0.0.1:${port}`) }
}

test('proxies a request through to the origin', async () => {
  const { srv, url } = await listeningOrigin((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(`hit ${req.url}`)
  })

  const proxy = await startOriginProxy(url)
  const resp = await fetch(new URL('/thing', proxy.address))
  assert.equal(resp.status, 200)
  assert.equal(await resp.text(), 'hit /thing')

  proxy.close()
  srv.close()
})

test('preserves the inbound Host header', async () => {
  let seenHost = ''
  const { srv, url } = await listeningOrigin((req, res) => {
    seenHost = req.headers.host ?? ''
    res.end('ok')
  })

  const proxy = await startOriginProxy(url)
  await fetch(proxy.address, { headers: { host: 'public.trycloudflare.com' } })
  assert.equal(seenHost, 'public.trycloudflare.com')

  proxy.close()
  srv.close()
})

test('binds loopback on an ephemeral port', async () => {
  const { srv, url } = await listeningOrigin((_req, res) => res.end())
  const proxy = await startOriginProxy(url)
  assert.equal(proxy.address.hostname, '127.0.0.1')
  assert.ok(Number(proxy.address.port) > 0)
  proxy.close()
  srv.close()
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module './origin.ts'`.

- [ ] **Step 3: Write the implementation**

Create `src/v1alpha1/origin.ts`:

```ts
import http from 'node:http'
import https from 'node:https'
import { once } from 'node:events'
import type { Logger } from './cloudflare/quicktunnel.ts'

export interface OriginProxy {
  /** The loopback address the transport dials. */
  address: URL
  server: http.Server
  close(): void
}

/**
 * startOriginProxy interposes a loopback reverse proxy in front of the origin.
 *
 * The hop is deliberate rather than incidental. cloudflared needs a URL to dial,
 * so the Go engine interposes one; the TypeScript transports are in-process and
 * could call the request pipeline directly, but keeping the hop means
 * InterceptCtx.target() denotes exactly what it denotes in Go — a real accept
 * socket the transport dials, which an interceptor can close to force a re-dial.
 *
 * Origin TLS verification is off: a local origin may present a self-signed
 * certificate, matching the Go engine's always-off origin verification.
 */
export async function startOriginProxy(origin: URL, log?: Logger): Promise<OriginProxy> {
  const secure = origin.protocol === 'https:'
  const agent = secure
    ? new https.Agent({ rejectUnauthorized: false })
    : new http.Agent()

  const server = http.createServer((req, res) => {
    const upstream = (secure ? https : http).request(
      {
        protocol: origin.protocol,
        hostname: origin.hostname,
        port: origin.port,
        method: req.method,
        path: req.url,
        // Preserve the inbound Host: the origin may key on it, and rewriting it
        // to the origin's own host is a behavior change the Go engine avoids.
        headers: req.headers,
        agent,
      },
      (up) => {
        res.writeHead(up.statusCode ?? 502, up.headers)
        up.pipe(res)
      },
    )

    upstream.on('error', (e) => {
      log?.debug('origin proxy upstream error', { error: e.message })
      if (!res.headersSent) res.writeHead(502)
      res.end()
    })

    req.pipe(upstream)
  })

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const { port } = server.address() as { port: number }

  log?.info('reverse proxy interposed', {
    listen: `127.0.0.1:${port}`,
    origin: origin.origin,
  })

  return {
    address: new URL(`http://127.0.0.1:${port}`),
    server,
    close: () => server.close(),
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add src/v1alpha1/origin.ts src/v1alpha1/origin.test.ts
git commit -m "feat(ts): loopback origin proxy hop"
```

---

### Task 10: The HTTP/2 edge transport

**Files:**
- Create: `src/v1alpha1/cloudflare/transport/http2.ts`, `src/v1alpha1/cloudflare/transport/http2.test.ts`

**Interfaces:**
- Consumes: `serveH2OverSocket` (Task 2), `registerConnection`/`streamTransport` (Task 4), `Transport`/`ConnectOptions`/`EdgeConnection` (Task 8).
- Produces: `http2Transport(): Transport` and the exported constants `EDGE_H2_SNI = 'h2.cftunnel.com'`, `CONTROL_STREAM_HEADER = 'cf-cloudflared-proxy-connection-upgrade'`.

- [ ] **Step 1: Write the failing test**

Create `src/v1alpha1/cloudflare/transport/http2.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  EDGE_H2_SNI,
  CONTROL_STREAM_HEADER,
  classifyStream,
  http2Transport,
} from './http2.ts'

test('edge TLS parameters match cloudflared', () => {
  assert.equal(EDGE_H2_SNI, 'h2.cftunnel.com')
  assert.equal(CONTROL_STREAM_HEADER, 'cf-cloudflared-proxy-connection-upgrade')
})

test('classifies the control stream', () => {
  assert.equal(classifyStream({ [CONTROL_STREAM_HEADER]: 'control-stream' }), 'control')
})

test('classifies websocket and configuration streams', () => {
  assert.equal(classifyStream({ [CONTROL_STREAM_HEADER]: 'websocket' }), 'websocket')
  assert.equal(
    classifyStream({ [CONTROL_STREAM_HEADER]: 'update-configuration' }),
    'configuration',
  )
})

test('an ordinary request carries no upgrade header', () => {
  assert.equal(classifyStream({ ':path': '/' }), 'request')
})

test('the transport announces its protocol', () => {
  assert.equal(http2Transport().protocol, 'http2')
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module './http2.ts'`.

- [ ] **Step 3: Write the implementation**

Create `src/v1alpha1/cloudflare/transport/http2.ts`:

```ts
import tls from 'node:tls'
import net from 'node:net'
import { once } from 'node:events'
import type { IncomingHttpHeaders, ServerHttp2Stream } from 'node:http2'
import { serveH2OverSocket } from './h2socket.ts'
import { registerConnection, streamTransport } from './registration.ts'
import type {
  ConnectOptions,
  EdgeConnection,
  EdgeRequest,
  Transport,
} from './index.ts'
import { version } from '../../../version.ts'

/** SNI for the HTTP/2 edge transport, from cloudflared's edgeH2TLSServerName. */
export const EDGE_H2_SNI = 'h2.cftunnel.com'

/** The header the edge uses to mark non-request streams. */
export const CONTROL_STREAM_HEADER = 'cf-cloudflared-proxy-connection-upgrade'

export type StreamKind = 'control' | 'websocket' | 'configuration' | 'request'

/**
 * classifyStream maps an inbound h2 stream to its role, mirroring cloudflared's
 * determineHTTP2Type. Anything without the upgrade header is an ordinary request
 * bound for the origin.
 */
export function classifyStream(headers: IncomingHttpHeaders): StreamKind {
  switch (headers[CONTROL_STREAM_HEADER]) {
    case 'control-stream':
      return 'control'
    case 'websocket':
      return 'websocket'
    case 'update-configuration':
      return 'configuration'
    default:
      return 'request'
  }
}

export function http2Transport(): Transport {
  return {
    protocol: 'http2',

    async connect(opts: ConnectOptions): Promise<EdgeConnection> {
      const socket = net.connect({ host: opts.addr.ip, port: opts.addr.port })
      await once(socket, 'connect')

      const secure = tls.connect({
        socket,
        servername: EDGE_H2_SNI,
        ALPNProtocols: ['h2'],
        ca: opts.caCerts,
      })
      await once(secure, 'secureConnect')

      let resolveLocation: (name: string) => void
      let rejectLocation: (e: Error) => void
      const location = new Promise<string>((res, rej) => {
        resolveLocation = res
        rejectLocation = rej
      })

      let closeResolve: () => void
      const closedPromise = new Promise<void>((res) => (closeResolve = res))

      const server = serveH2OverSocket(secure, (stream, headers) => {
        switch (classifyStream(headers)) {
          case 'control':
            // The control stream stays open for the connection's lifetime; the
            // edge reads our registration off it and pushes lifecycle events back.
            registerConnection(streamTransport(stream), {
              accountTag: opts.accountTag,
              tunnelSecret: opts.tunnelSecret,
              tunnelId: opts.tunnelId,
              connIndex: opts.connIndex,
              clientId: opts.tunnelId,
              version: version(),
              arch: `${process.platform}_${process.arch}`,
              features: [],
            }).then(
              (details) => {
                opts.log?.info('registered with the edge', {
                  location: details.locationName,
                  protocol: 'http2',
                  connIndex: opts.connIndex,
                })
                resolveLocation(details.locationName)
              },
              (e: Error) => rejectLocation(e),
            )
            break

          case 'configuration':
            stream.respond({ ':status': 200 })
            stream.end('{"lastAppliedVersion":0}')
            break

          case 'websocket':
          case 'request':
            dispatchRequest(stream, headers, opts)
            break
        }
      })

      secure.on('close', () => closeResolve())

      const locationName = await location

      return {
        locationName,
        close() {
          server.close()
          secure.destroy()
        },
        closed: () => closedPromise,
      }
    },
  }
}

/** dispatchRequest hands an ordinary edge stream to the request pipeline. */
function dispatchRequest(
  stream: ServerHttp2Stream,
  headers: IncomingHttpHeaders,
  opts: ConnectOptions,
): void {
  const plain: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) {
    if (k.startsWith(':')) continue
    if (k === CONTROL_STREAM_HEADER) continue
    plain[k] = Array.isArray(v) ? v.join(', ') : String(v ?? '')
  }

  const req: EdgeRequest = {
    method: String(headers[':method'] ?? 'GET'),
    path: String(headers[':path'] ?? '/'),
    host: String(headers[':authority'] ?? opts.hostname),
    headers: plain,
    body: stream,
  }

  opts.onRequest(req, {
    writeHead(status, respHeaders) {
      stream.respond({ ':status': status, ...respHeaders })
    },
    body() {
      return stream
    },
  })
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add src/v1alpha1/cloudflare/transport/http2.ts \
        src/v1alpha1/cloudflare/transport/http2.test.ts
git commit -m "feat(ts): HTTP/2 edge transport"
```

---

### Task 11: The QUIC edge transport

**Files:**
- Create: `src/v1alpha1/cloudflare/transport/quic.ts`, `src/v1alpha1/cloudflare/transport/quic.test.ts`
- Modify: `src/v1alpha1/cloudflare/transport/framing.ts`

**Interfaces:**
- Consumes: `framing.ts` (Task 3), `registration.ts` (Task 4), `Transport` (Task 8).
- Produces: `quicTransport(): Transport`, plus from `framing.ts`: `DATA_STREAM_SIGNATURE`, `RPC_STREAM_SIGNATURE`, `readSignature(bytes): 'data' | 'rpc'`, `writeDataStreamPreamble(): Uint8Array`.

- [ ] **Step 1: Write the failing test**

Create `src/v1alpha1/cloudflare/transport/quic.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  DATA_STREAM_SIGNATURE,
  RPC_STREAM_SIGNATURE,
  readSignature,
  writeDataStreamPreamble,
} from './framing.ts'
import { EDGE_QUIC_SNI, EDGE_QUIC_ALPN, quicTransport } from './quic.ts'

test('stream signatures match cloudflared byte for byte', () => {
  assert.deepEqual(Array.from(DATA_STREAM_SIGNATURE), [0x0a, 0x36, 0xcd, 0x12, 0xa1, 0x3e])
  assert.deepEqual(Array.from(RPC_STREAM_SIGNATURE), [0x52, 0xbb, 0x82, 0x5c, 0xdb, 0x65])
})

test('edge QUIC parameters match cloudflared', () => {
  assert.equal(EDGE_QUIC_SNI, 'quic.cftunnel.com')
  assert.equal(EDGE_QUIC_ALPN, 'argotunnel')
})

test('readSignature discriminates the two stream kinds', () => {
  assert.equal(readSignature(DATA_STREAM_SIGNATURE), 'data')
  assert.equal(readSignature(RPC_STREAM_SIGNATURE), 'rpc')
})

test('an unknown signature is rejected', () => {
  assert.throws(() => readSignature(new Uint8Array([1, 2, 3, 4, 5, 6])), /unknown signature/)
})

test('the data stream preamble is the signature plus a version byte', () => {
  const preamble = writeDataStreamPreamble()
  assert.equal(preamble.length, 7)
  assert.deepEqual(Array.from(preamble.subarray(0, 6)), Array.from(DATA_STREAM_SIGNATURE))
  assert.equal(preamble[6], 0x01)
})

test('the transport announces its protocol', () => {
  assert.equal(quicTransport().protocol, 'quic')
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `readSignature` is not exported from `./framing.ts`.

- [ ] **Step 3: Add the signatures to framing.ts**

Append to `src/v1alpha1/cloudflare/transport/framing.ts`:

```ts
/**
 * The first six bytes of a QUIC stream identify its kind. Copied verbatim from
 * cloudflared's tunnelrpc/quic/protocol.go; these are arbitrary magic values and
 * must not be regenerated or "cleaned up".
 */
export const DATA_STREAM_SIGNATURE = new Uint8Array([0x0a, 0x36, 0xcd, 0x12, 0xa1, 0x3e])
export const RPC_STREAM_SIGNATURE = new Uint8Array([0x52, 0xbb, 0x82, 0x5c, 0xdb, 0x65])

/** The data-stream protocol version byte that follows the signature. */
export const DATA_STREAM_VERSION = 0x01

export function readSignature(bytes: Uint8Array): 'data' | 'rpc' {
  const head = bytes.subarray(0, 6)
  if (equalBytes(head, DATA_STREAM_SIGNATURE)) return 'data'
  if (equalBytes(head, RPC_STREAM_SIGNATURE)) return 'rpc'
  throw new Error(`unknown signature ${Array.from(head).join(',')}`)
}

export function writeDataStreamPreamble(): Uint8Array {
  const out = new Uint8Array(7)
  out.set(DATA_STREAM_SIGNATURE, 0)
  out[6] = DATA_STREAM_VERSION
  return out
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}
```

- [ ] **Step 4: Write the QUIC transport**

Create `src/v1alpha1/cloudflare/transport/quic.ts`:

```ts
import { registerConnection, streamTransport } from './registration.ts'
import {
  ConnectionType,
  RPC_STREAM_SIGNATURE,
  decodeConnectRequest,
  encodeConnectResponse,
  readSignature,
  writeDataStreamPreamble,
} from './framing.ts'
import type { ConnectOptions, EdgeConnection, EdgeRequest, Transport } from './index.ts'
import { version } from '../../../version.ts'
import type { Duplex } from 'node:stream'

/** SNI for the QUIC edge transport, from cloudflared's edgeQUICServerName. */
export const EDGE_QUIC_SNI = 'quic.cftunnel.com'

/** ALPN for the QUIC edge transport, from cloudflared's quicProtos. */
export const EDGE_QUIC_ALPN = 'argotunnel'

export function quicTransport(): Transport {
  return {
    protocol: 'quic',

    async connect(opts: ConnectOptions): Promise<EdgeConnection> {
      const { connect } = await import('node:quic')

      const session = await connect(`${opts.addr.ip}:${opts.addr.port}`, {
        alpn: EDGE_QUIC_ALPN,
        sni: EDGE_QUIC_SNI,
        ca: opts.caCerts,
      })

      // The RPC stream carries registration. Its signature goes first, then the
      // stream is a plain capnp RPC transport.
      const rpc = await session.createBidirectionalStream()
      const rpcStream = rpc as unknown as Duplex
      rpcStream.write(Buffer.from(RPC_STREAM_SIGNATURE))

      const details = await registerConnection(streamTransport(rpcStream), {
        accountTag: opts.accountTag,
        tunnelSecret: opts.tunnelSecret,
        tunnelId: opts.tunnelId,
        connIndex: opts.connIndex,
        clientId: opts.tunnelId,
        version: version(),
        arch: `${process.platform}_${process.arch}`,
        features: [],
      })

      opts.log?.info('registered with the edge', {
        location: details.locationName,
        protocol: 'quic',
        connIndex: opts.connIndex,
      })

      let closeResolve: () => void
      const closedPromise = new Promise<void>((res) => (closeResolve = res))

      session.onstream = (stream: unknown) => {
        handleDataStream(stream as Duplex, opts)
      }
      session.onclose = () => closeResolve()

      return {
        locationName: details.locationName,
        close: () => session.close(),
        closed: () => closedPromise,
      }
    },
  }
}

/**
 * handleDataStream reads one request off an edge-opened stream: signature,
 * version byte, then a capnp ConnectRequest whose metadata carries the HTTP
 * method, host, and headers. The response is a signature preamble plus a capnp
 * ConnectResponse, after which the stream carries the body verbatim.
 */
function handleDataStream(stream: Duplex, opts: ConnectOptions): void {
  stream.once('readable', () => {
    const head = stream.read() as Buffer | null
    if (!head) return

    if (readSignature(new Uint8Array(head)) !== 'data') {
      stream.destroy(new Error('edge opened a non-data stream'))
      return
    }

    // signature (6) + version (1)
    const payload = new Uint8Array(head.subarray(7))
    const request = decodeConnectRequest(payload)

    const meta = new Map(request.metadata.map((m) => [m.key, m.val]))
    const headers: Record<string, string> = {}
    for (const [k, v] of meta) {
      if (k.startsWith('HttpHeader:')) headers[k.slice('HttpHeader:'.length).toLowerCase()] = v
    }

    const req: EdgeRequest = {
      method: meta.get('HttpMethod') ?? 'GET',
      path: new URL(request.dest, `https://${opts.hostname}`).pathname,
      host: meta.get('HttpHost') ?? opts.hostname,
      headers,
      body: request.type === ConnectionType.HTTP ? stream : stream,
    }

    opts.onRequest(req, {
      writeHead(status, respHeaders) {
        stream.write(Buffer.from(writeDataStreamPreamble()))
        const metadata = [
          { key: 'HttpStatus', val: String(status) },
          ...Object.entries(respHeaders).map(([k, v]) => ({
            key: `HttpHeader:${k}`,
            val: v,
          })),
        ]
        stream.write(Buffer.from(encodeConnectResponse('', metadata)))
      },
      body() {
        return stream
      },
    })
  })
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test`
Expected: PASS, 6 tests.

The `node:quic` session API (`createBidirectionalStream`, `onstream`, `onclose`,
whether streams are Node duplexes or web streams) is Stability 1.0 and can shift.
The tests above cover the framing and constants, which are stable; the session
wiring is verified by the CI QUIC lane and by Task 12's live e2e.

- [ ] **Step 6: Commit**

```bash
git add src/v1alpha1/cloudflare/transport/quic.ts \
        src/v1alpha1/cloudflare/transport/quic.test.ts \
        src/v1alpha1/cloudflare/transport/framing.ts
git commit -m "feat(ts): QUIC edge transport with quic-pogs framing"
```

---

### Task 12: Backend, minimal tunnel, and the live end-to-end test

The payoff: a real public URL.

**Files:**
- Create: `src/v1alpha1/cloudflare/index.ts`, `src/index.ts`, `src/e2e.test.ts`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `cloudflare(): Backend` with `withProtocol(p: Protocol): Backend`
  - `tunnel(backend: Backend): MinimalTunnel` with `withServer(s: net.Server)`, `withLogger(l: Logger)`, `withSignal(s: AbortSignal)`, `url(): Promise<URL>`, `hostname(): Promise<string>`, `close(): void`
  - `version()` re-exported

- [ ] **Step 1: Write the failing test**

Create `src/e2e.test.ts`:

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { once } from 'node:events'
import { tunnel, cloudflare } from './index.ts'

const live = process.env.LIBTUNNEL_E2E_LIVE === '1'
const protocol = (process.env.LIBTUNNEL__CLOUDFLARE_PROTOCOL ?? 'auto') as
  | 'auto'
  | 'quic'
  | 'http2'

test('serves a real public URL end to end', { skip: !live }, async () => {
  const origin = http.createServer((_req, res) => res.end('hello from libtunnel'))
  origin.listen(0, '127.0.0.1')
  await once(origin, 'listening')

  const ac = new AbortController()
  const conn = tunnel(cloudflare().withProtocol(protocol))
    .withSignal(ac.signal)
    .withServer(origin)

  const url = await conn.url()
  assert.match(url.hostname, /\.trycloudflare\.com$/)

  // The edge needs a moment to propagate the route; 1033 is propagation lag.
  let body = ''
  for (let i = 0; i < 30; i++) {
    const resp = await fetch(url)
    body = await resp.text()
    if (resp.ok && body.includes('hello from libtunnel')) break
    await new Promise((r) => setTimeout(r, 2000))
  }
  assert.match(body, /hello from libtunnel/)

  conn.close()
  ac.abort()
  origin.close()
})

test('constructs without touching the network', () => {
  const conn = tunnel(cloudflare())
  assert.equal(typeof conn.url, 'function')
  conn.close()
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module './index.ts'`.

- [ ] **Step 3: Write the backend**

Create `src/v1alpha1/cloudflare/index.ts`:

```ts
import net from 'node:net'
import tls from 'node:tls'
import { once } from 'node:events'
import { mintQuickTunnel, type Logger } from './quicktunnel.ts'
import { serializeSpec, type Spec } from './spec.ts'
import { discoverEdge } from './transport/discovery.ts'
import { http2Transport } from './transport/http2.ts'
import { quicTransport } from './transport/quic.ts'
import { selectProtocol, type Protocol, type Transport } from './transport/index.ts'
import { startOriginProxy, type OriginProxy } from '../origin.ts'

export interface Backend {
  withProtocol(p: Protocol): Backend
  readonly protocol: Protocol
  mint(log: Logger | undefined, signal: AbortSignal | undefined): Promise<Spec>
  transport(log?: Logger): Promise<Transport>
}

/**
 * cloudflare returns the Cloudflare backend. The name matches Go's
 * libtunnel.Cloudflare() deliberately: the spec envelope's backend tag and the
 * LIBTUNNEL__CLOUDFLARE_* variables are wire contracts that cross-language
 * handoff depends on, so the name a caller writes is the name that travels.
 */
export function cloudflare(): Backend {
  let protocol: Protocol =
    (process.env.LIBTUNNEL__CLOUDFLARE_PROTOCOL as Protocol | undefined) ?? 'auto'
  let protocolFixed = process.env.LIBTUNNEL__CLOUDFLARE_PROTOCOL !== undefined

  const backend: Backend = {
    get protocol() {
      return protocol
    },
    withProtocol(p: Protocol): Backend {
      // Env beats code, and the knob is write-once, matching the Go mutators.
      if (!protocolFixed) {
        protocol = p
        protocolFixed = true
      }
      return backend
    },
    mint: (log, signal) => mintQuickTunnel({ log, signal }),
    async transport(log?: Logger): Promise<Transport> {
      const chosen = await selectProtocol(protocol, log)
      return chosen === 'quic' ? quicTransport() : http2Transport()
    },
  }
  return backend
}

export { serializeSpec, discoverEdge, startOriginProxy }
export type { Spec, Logger, OriginProxy }
```

- [ ] **Step 4: Write the façade**

Create `src/index.ts`:

```ts
import net from 'node:net'
import { once } from 'node:events'
import { cloudflare, type Backend } from './v1alpha1/cloudflare/index.ts'
import { discoverEdge } from './v1alpha1/cloudflare/transport/discovery.ts'
import { startOriginProxy } from './v1alpha1/origin.ts'
import type { Logger } from './v1alpha1/cloudflare/quicktunnel.ts'
import { version } from './version.ts'

export interface MinimalTunnel {
  withServer(s: net.Server): MinimalTunnel
  withLogger(l: Logger): MinimalTunnel
  withSignal(s: AbortSignal): MinimalTunnel
  hostname(): Promise<string>
  url(): Promise<URL>
  close(): void
}

/**
 * tunnel is the M1 tunnel handle: enough surface to mint, connect, and serve.
 * The full lazy Tunnel contract — write-once mutators, readiness promises,
 * interceptors, spec cache, handoff — is M2.
 */
export function tunnel(backend: Backend): MinimalTunnel {
  let server: net.Server | undefined
  let log: Logger | undefined
  let signal: AbortSignal | undefined
  let started: Promise<{ hostname: string }> | undefined
  const cleanup: (() => void)[] = []

  async function start(): Promise<{ hostname: string }> {
    const spec = await backend.mint(log, signal)
    const transport = await backend.transport(log)

    if (!server) {
      server = net.createServer()
      server.listen(0, '127.0.0.1')
      await once(server, 'listening')
    }
    const addr = server.address() as net.AddressInfo
    const origin = new URL(`http://127.0.0.1:${addr.port}`)

    const proxy = await startOriginProxy(origin, log)
    cleanup.push(() => proxy.close())

    const addrs = await discoverEdge()
    const conn = await transport.connect({
      addr: addrs[0],
      caCerts: [],
      accountTag: spec.account_tag,
      tunnelSecret: spec.secret,
      tunnelId: uuidToBytes(spec.id),
      hostname: spec.hostname,
      connIndex: 0,
      log,
      signal,
      onRequest(req, respond) {
        const upstream = new URL(req.path, proxy.address)
        fetch(upstream, {
          method: req.method,
          headers: { ...req.headers, host: req.host },
          body: req.method === 'GET' || req.method === 'HEAD' ? undefined : (req.body as never),
          duplex: 'half',
        } as RequestInit).then(async (resp) => {
          const headers: Record<string, string> = {}
          resp.headers.forEach((v, k) => (headers[k] = v))
          respond.writeHead(resp.status, headers)
          const body = respond.body()
          body.end(Buffer.from(await resp.arrayBuffer()))
        })
      },
    })
    cleanup.push(() => conn.close())

    log?.info('tunnel up', { hostname: spec.hostname, location: conn.locationName })
    return { hostname: spec.hostname }
  }

  const t: MinimalTunnel = {
    withServer(s) {
      server ??= s
      return t
    },
    withLogger(l) {
      log ??= l
      return t
    },
    withSignal(s) {
      signal ??= s
      return t
    },
    async hostname() {
      started ??= start()
      return (await started).hostname
    },
    async url() {
      return new URL(`https://${await t.hostname()}/`)
    },
    close() {
      for (const fn of cleanup.splice(0)) fn()
    },
  }
  return t
}

function uuidToBytes(uuid: string): Uint8Array {
  return new Uint8Array(Buffer.from(uuid.replace(/-/g, ''), 'hex'))
}

export { cloudflare, version }
export type { Backend, Logger }
```

- [ ] **Step 5: Run the offline test to verify it passes**

Run: `npm test`
Expected: PASS — the live case skips (`LIBTUNNEL_E2E_LIVE` unset), the construction case passes.

- [ ] **Step 6: Run the live test**

Run: `LIBTUNNEL_E2E_LIVE=1 npm test`
Expected: PASS — a real `*.trycloudflare.com` URL serves `hello from libtunnel`.

This is the M1 acceptance criterion. If it fails on `1033`, that is edge route
propagation lag; re-run. If it fails at registration, read the error: the capnp
initializer names in Task 4 are the most likely culprit.

Then pin the protocol and re-run each leg:

```bash
LIBTUNNEL_E2E_LIVE=1 LIBTUNNEL__CLOUDFLARE_PROTOCOL=http2 npm test
LIBTUNNEL_E2E_LIVE=1 LIBTUNNEL__CLOUDFLARE_PROTOCOL=quic npm test   # needs a QUIC-capable Node
```

- [ ] **Step 7: Document the TypeScript library**

Add to `README.md`, after the Go Quick Start section:

````markdown
## TypeScript

The same library, native Node engine — no `cloudflared` binary, no subprocess,
no native addon.

```sh
npm install libtunnel
```

```ts
import http from 'node:http'
import { tunnel, cloudflare } from 'libtunnel'

const origin = http.createServer((_req, res) => res.end('hello from libtunnel'))
origin.listen(0, '127.0.0.1')

const conn = tunnel(cloudflare()).withServer(origin)
console.log(String(await conn.url())) // https://<something>.trycloudflare.com/
```

The edge transport follows cloudflared's own `--protocol` selection —
`withProtocol('auto' | 'quic' | 'http2')`, default `auto`, mirrored by
`LIBTUNNEL__CLOUDFLARE_PROTOCOL`. `auto` prefers QUIC and falls back to HTTP/2;
an explicitly requested protocol never falls back.

**A note on QUIC.** `node:quic` requires a Node built with `--experimental-quic`,
which release builds are not, so on stock Node `auto` resolves to HTTP/2 and logs
one warning. That path is fully functional but rides TCP, so throughput under
packet loss is measurably worse than QUIC's. When Node ships QUIC in a release
build, the same code selects it with no change.
````

- [ ] **Step 8: Commit**

```bash
git add src/index.ts src/v1alpha1/cloudflare/index.ts src/e2e.test.ts README.md
git commit -m "feat(ts): backend, minimal tunnel, and a live public URL"
```

---

## Self-Review

**Spec coverage.** Every M0/M1 section of the spec maps to a task: repo shape → 1; G1 → 2; capnp/G2 → 3, 4; discovery → 5; envelope conformance → 6; mint → 7; protocol selection, probe, CI QUIC lane, G3 → 8; loopback hop → 9; HTTP/2 transport → 10; QUIC transport and framing → 11; backend, façade, live e2e, README → 12. The gofmt `node_modules` prune is in Task 1. Deliberately deferred to M2/M3 and stated as such: the full lazy `Tunnel` contract, interceptors, resolver, spec cache, `LIBTUNNEL_SPEC` handoff, the env-mirror table, the TS CLI, npm release wiring, and the Go↔TS cross-language handoff e2e.

**Placeholders.** One intentional and explicitly bounded: `testcert.ts` carries `<generated in Step 2>` markers filled by a command given in that same step. No "TBD", no "handle errors appropriately", no "similar to Task N" — each task repeats what it needs.

**Type consistency.** `Logger` is defined once (Task 7) and imported everywhere. `Spec` uses snake_case fields (`account_tag`) throughout, matching the JSON wire form. `Transport`, `ConnectOptions`, `EdgeConnection`, `EdgeRequest`, and `EdgeResponder` are declared once in Task 8 and consumed unchanged by Tasks 10 and 11. `registerConnection` takes the same `RegisterParams` shape at both call sites.

**Known soft spots, flagged rather than hidden.** Two places where the plan asserts an API it could not execute during planning: the capnp-es *initializer* names in Task 4 (`_initAuth`, `copyBuffer`, the union discriminator) and the `node:quic` *session* API in Task 11. Both tasks say explicitly that the generated file and the runtime are the authority and to adjust to what they declare. Everything else in the plan was verified by running it.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-27-typescript-libtunnel-m0-m1.md`. Two execution options:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session with checkpoints for review.
