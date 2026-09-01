# Disambiguating tunnel failures: `ErrFailed` and a global classifier

Design for [#162](https://github.com/cnuss/libtunnel/issues/162).

## Problem

A mint that can never succeed is indistinguishable, from outside the library,
from one that is still working.

`QuickTunnelProvider.Spec` retries every error except `ErrMintRejected`
forever (`v1alpha1/cloudflare/quicktunnel.go:228-265`). The only exit is the
caller's context. A container with no CA bundle therefore loops on

```
tls: failed to verify certificate: x509: certificate signed by unknown authority
```

indefinitely: `URL()` never returns, `Done()` never closes, `Err()` stays nil,
and a caller running the default silent logger sees zero bytes. A caller that
passed `context.Background()` has no exit at all.

The machinery to report this already exists and never runs.
`TunnelImpl.Spec` (`v1alpha1/tunnel.go:605-611`) turns a provider error into
`t.cancel(fmt.Errorf("unable to fetch tunnel spec: %w", err))`, which is
exactly what makes `Err()` report a cause and `Done()` close. It is starved
because `Spec` never returns.

Two things are wrong, and both are libtunnel's job:

1. **No terminal state.** Some failures can never be retried away; others can
   be, but not forever.
2. **No vocabulary.** When a failure does surface it surfaces as prose, so a
   caller deciding whether `x509: certificate signed by unknown authority` is
   retryable must match on the text of an error it did not construct — and
   every caller must then do it again, and keep it correct as the text
   changes.

## Prior art, and what it settles

| Source | What it does | What it settles here |
|---|---|---|
| [`net.Error.Temporary`](https://pkg.go.dev/net#Error) | Deprecated: *"Temporary errors are not well-defined. Most 'temporary' errors are timeouts, and the few exceptions are surprising. Do not use this method."* | Do not export a `Retryable() bool` on the error. Retryability is a property of a named class, decided in one place. |
| [`cenkalti/backoff/v5`](https://pkg.go.dev/github.com/cenkalti/backoff/v5), `avast/retry-go` | `Permanent(err)` / `Unrecoverable(err)` short-circuits the loop; `MaxElapsedTime` (default 15m) ends it regardless | Both mechanisms, always. Nothing in the prior art ships an unbounded loop. |
| [`k8s.io/apimachinery/pkg/api/errors`](https://pkg.go.dev/k8s.io/apimachinery/pkg/api/errors) | `StatusError` + `StatusReason` enum + `ReasonForError` + `IsNotFound`/`IsConflict`/… predicates. `SuggestsClientDelay() (seconds, bool)` deliberately separates the delay hint from whether to retry at all | An enum is never the caller-facing surface on its own. And a `Retry-After` is a *duration*, not a verdict — libtunnel conflates the two in today's `ErrRateLimited`. |
| [`containerd/errdefs`](https://github.com/containerd/errdefs) | 15 sentinels + `IsXXX()` helpers | Sentinels alone carry a taxonomy fine when the space is small. libtunnel's is five and locally decided; k8s's is ~20 and grows with a wire protocol. |
| [`hashicorp/go-retryablehttp`](https://pkg.go.dev/github.com/hashicorp/go-retryablehttp) | `baseRetryPolicy` hard-codes four non-retryables: too many redirects, invalid scheme, invalid header, TLS cert verification failure. Exhaustion returns `"giving up after %d attempt(s): %w"` | "Cert verification failure is never retryable" is a settled default, not our judgment call. And the exhaustion error keeps the cause wrapped. |
| [`cloudflared/supervisor`](https://github.com/cloudflare/cloudflared/blob/master/supervisor/tunnel.go) | `ServerRegisterTunnelError{Permanent bool}`, hard non-retryable `DupConnRegisterTunnelError` / `EdgeQuicDialError`, unmarked defaults retryable, `maxRetries` ceiling | The domain-nearest library is already libtunnel's split — permanent-marked vs everything-else — plus the ceiling libtunnel lacks. |

libtunnel also solved this once already, on the other path. `v1.ErrEdgeUnreachable`
(`v1/v1.go:27-32`) is bounded-retry-ends-in-a-sentinel, and
`v1alpha1/cloudflare/cloudflare.go:845-855` reports it with attempt count,
elapsed time and a hint. Its doc comment states #162's own argument verbatim:
*"without a bound a blocked network is indistinguishable from a slow one and
the tunnel hangs until the caller's context expires."* The mint path never got
the same treatment. This design gives it that treatment and unifies the two.

## Design

### 1. Vocabulary — `v1/v1.go`

A failure class is a terminal tunnel state: the umbrella it belongs to, the
reason it will not come up, and how long that class may keep failing before it
becomes the verdict. Carrying the budget on the class is what removes the two
things that would otherwise have to be kept in sync by hand — a `Budget`
lookup table, and a separate "is this retryable" boolean.

```go
// ErrFailed marks a tunnel that will not come up. Retrying will not help; the
// class wrapping it says what an operator can do about it.
var ErrFailed = errors.New("tunnel failed")

// class is a terminal tunnel state. parent is the umbrella it answers to, or
// nil for a state that is not a failure. budget is how long the class may
// keep failing before it becomes the verdict; zero never retries.
type class struct {
	parent error
	reason string
	budget time.Duration
}

func (c *class) Error() string {
	if c.parent == nil {
		return c.reason
	}
	return c.parent.Error() + ": " + c.reason
}

func (c *class) Is(target error) bool { return c.parent != nil && errors.Is(c.parent, target) }

var (
	// ErrCertificate is the Err result of a tunnel whose provider's
	// certificate could not be verified — no trust store, a wrong system
	// clock, or an intercepting proxy. No retry changes any of those.
	ErrCertificate error = &class{ErrFailed, "certificate verification", 0}

	// ErrRejected is the Err result of a mint the provider definitively
	// refused, or of a request libtunnel could not construct at all.
	ErrRejected error = &class{ErrFailed, "rejected by the provider", 0}

	// ErrProviderUnreachable is the Err result of a mint endpoint that does
	// not resolve, refuses, times out or keeps 5xx-ing past its budget.
	ErrProviderUnreachable error = &class{ErrFailed, "provider unreachable", 45 * time.Second}

	// ErrEdgeUnreachable is the Err result of a tunnel that never reached its
	// backend's edge.
	ErrEdgeUnreachable error = &class{ErrFailed, "edge unreachable", 30 * time.Second}

	// ErrRateLimited is the Err result of a mint rate limited past its
	// budget, or rate limited with an advertised reset longer than it.
	ErrRateLimited error = &class{ErrFailed, "rate limited", 45 * time.Second}

	// ErrClosed is the Err result of a tunnel shut down deliberately. It is
	// terminal but it is not a failure, so it has no umbrella: its Error() is
	// bare "tunnel closed" and errors.Is(err, ErrFailed) is false.
	ErrClosed error = &class{nil, "tunnel closed", 0}
)

// Budget reports how long the class err belongs to may keep failing before it
// becomes the verdict. Zero — including for anything that is not a failure
// class at all — never retries.
func Budget(err error) time.Duration
```

Declaring the vars `error`-typed keeps `class` out of godoc; `Budget` is the
only accessor, so no caller ever names the type.

The relations this produces, verified rather than assumed:

```
err := fmt.Errorf("unable to fetch tunnel spec: %w",
    fmt.Errorf("%w: %w", ErrCertificate, cause))

msg:                       unable to fetch tunnel spec: tunnel failed: certificate verification: x509: …
Is(err, ErrCertificate)    true      Is(err, ErrFailed)        true
Is(err, ErrRejected)       false     Is(err, cause)            true
Is(ErrClosed, ErrFailed)   false     Budget(ErrRateLimited)    45s
```

**Two hops, two classes.** `ErrProviderUnreachable` and `ErrEdgeUnreachable`
are deliberately not folded together. The operator advice differs, which is
the point of having a taxonomy at all: an unreachable edge means egress to
port 7844 is blocked and `WithEdge` is the way around it
(`edgeBlockedHint`, `cloudflare.go:878-882`); an unreachable provider means no
route to the mint API. They also hold different budgets, derived from
different constraints — see §3 — and one class cannot hold both. "Timeout"
would not distinguish them either: every retryable class is a timeout once it
has a budget. The hop is what differs.

**Removed:** `v1.ErrHostnameUnresolved` (already vestigial — readiness has
followed the edge connection registering since the mint provider started
waiting out DNS propagation), `cloudflare.ErrMintRejected` and
`cloudflare.ErrRateLimited` (`quicktunnel.go:24-32`), and the
`cloudflare.edgeTimeout` const (`cloudflare.go:876`), whose 30s now lives on
`ErrEdgeUnreachable` and whose justification comment moves with it.

This is a breaking change to `v1`. It is taken deliberately: the package has
one consumer today, and carrying two vocabularies to avoid it would cost more
than the break.

**Known tension.** `ErrEdgeUnreachable`'s 30s is a Cloudflare fact living in
the backend-agnostic package. A second backend with a different edge would
want a different number and would have to either accept this one or consult
its own const, reintroducing the inconsistency this design removes. Accepted
for now because there is one backend; revisit when there are two.

### 2. The classifier — `v1alpha1/errors.go` (new file)

```go
// Classify names err with the v1 failure class that describes it. An error
// that already carries a class — a provider naming a verdict only its
// protocol can read — is returned as it arrived; everything else is read at
// the transport level, which every backend shares. Whether the result is
// worth retrying is v1.Budget(class) > 0, not a second return value.
func Classify(err error) error
```

Rules, in order:

| condition | class |
|---|---|
| already carries a `v1` failure class | that one |
| `tls.CertificateVerificationError`, `x509.UnknownAuthorityError`, `x509.HostnameError`, `x509.CertificateInvalidError` | `ErrCertificate` |
| `*url.Error` from an unsupported scheme or an invalid header | `ErrRejected` |
| `*net.DNSError` with `IsNotFound` (NXDOMAIN) | `ErrRejected` |
| anything else — refused, timeout, transient DNS, 5xx | `ErrProviderUnreachable` |

NXDOMAIN classifies as `ErrRejected` rather than as an unreachable host with a
zero budget: a name that does not exist is a configuration error, the same
class as a `WithApiURL` with a bad scheme, and giving it a class whose budget
is zero keeps "budget zero means never retry" true by construction rather than
by a special case.

**Provider classifiers fold in by construction, not by a second function.**
Cloudflare gets no `classify` of its own. `fetch` already knows the two
verdicts only the quick-tunnel protocol can read, so it names them at the
source — `v1.ErrRejected` for `success=false` under HTTP 500,
`v1.ErrRateLimited` for 429 — and returns everything else raw. `Classify`
recognizes the named ones by rule 1 and reads the rest. A future backend
needing protocol-level naming does the same: tag at the source, and let
`Classify` stay the only place a class is decided.

### 3. Budgets

The numbers live on the classes in §1. Their derivations:

**`ErrProviderUnreachable` — 45 seconds**, from the per-attempt bound already
in `quicktunnel.go:108-122`. The mint client carries `Timeout: 15 * time.Second`,
sized, per its own comment, so the header wait "must cover a full server-side
mint" while the endpoint waits out DNS propagation for the hostname. A hung
endpoint therefore burns 15s per attempt, so any budget under 30s cannot tell
a dead endpoint from one bad attempt. Three full attempts — 45s — is the
smallest bound that can.

For fast-failing errors (connection refused, SERVFAIL) the loop's `sleep += 1s`
ramp governs instead, and 45s buys about nine attempts, at 0s, 1s, 3s, 6s,
10s, 15s, 21s, 28s and 36s — comfortably outlasting a container resolver that
comes up late.

**`ErrEdgeUnreachable` — 30 seconds**, the value `edgeTimeout` already holds,
carried over with its reasoning intact: `edgeProtocol` pins the edge to TCP,
so there is no quic→http2 fallback in flight for a short bound to cut off. An
earlier version of that bound had to outlast the fallback and did not, failing
a CI runner after four QUIC attempts while http2 was still ahead of it. With
the transport fixed, a TCP connect and registration that has not happened in
thirty seconds is not going to. This is why it is not 45s: a different
constraint, a different number, which is what having two classes buys.

**`ErrRateLimited` — 45 seconds**, the same number as the provider class for an
admittedly weaker reason. The advertised reset does the real work here:
`quicktunnel.go:176-196` already parses `Retry-After` in both its seconds and
HTTP-date forms, so a server that names its reset is either waited out, when
it fits the budget, or reported immediately with the duration in the message.
The budget only governs the headerless 429 — the two branches at
`quicktunnel.go:192-196` that return no duration — where there is nothing to
key on but the ramp. We have no data on how long those last, so matching the
provider budget is a defensible default rather than a derived one.
*Assumption to revisit* if headerless 429s turn out to be common and
short-lived.

The retry loop reaches `v1.Budget` through an unexported package var in
`quicktunnel.go` — `var budget = v1.Budget` — which is the loop's test seam,
following the one `cloudflare_test.go:995` already establishes for the API
URL. That keeps `v1.Budget` a clean function rather than a mutable exported
var, and lets an internal test drive the loop to expiry in milliseconds
instead of 45 seconds.

### 4. The retry loop — `v1alpha1/cloudflare/quicktunnel.go`

The loop at `228-265` consults `Classify` on every error, at arrival, before
deciding to go round again:

```go
class := v1alpha1.Classify(err)
if budget(class) == 0 {
    return nil, fmt.Errorf("%w: %w", class, err)
}
if _, seen := since[class]; !seen {
    since[class] = time.Now()
}
if spent := time.Since(since[class]); spent > budget(class) {
    return nil, fmt.Errorf("%w: no spec after %d attempts in %s: %w",
        class, attempts, spent.Round(time.Second), err)
}
```

The clock is wall time since the class was first seen, not a sum of the
backoff waits. Summing the waits would undercount a hang by an order of
magnitude — three 15s timeouts cost 45s of real time but only 1s+2s+3s of
ramp — which is exactly the failure mode the budget exists to catch.

A 429 that advertises a reset longer than `budget(v1.ErrRateLimited)` also
short-circuits on arrival rather than being slept on, so the caller gets
"rate limited, resets in 5m" now, with the duration `quicktunnel.go:185-190`
already parsed.

The exhaustion message follows `cloudflare.go:854` — attempts, elapsed, cause
— which follows retryablehttp's `"giving up after %d attempt(s): %w"`.

`Spec` hands the sentinel up, `TunnelImpl.Spec` cancels with it, and `URL()`,
`Err()` and `Done()` report it through paths that exist today. **No change to
`v1alpha1/tunnel.go`** — its `fmt.Errorf("unable to fetch tunnel spec: %w", err)`
already preserves `errors.Is` down the chain.

### 5. Behavior that must survive

The reclaim path at `quicktunnel.go:235-243`. Today a cached spec the backend
refuses arrives as `ErrMintRejected`, and the loop drops the reclaim hints and
retries once immediately, because that verdict is about the reclaim and not
about a fresh mint. With `ErrMintRejected` gone this keys on `ErrRejected`
plus `len(hints) > 0`: drop hints, retry once, and a rejection of the retry is
terminal exactly as it is now.

The `Retry-After` handling at `quicktunnel.go:246-249` also survives — the
server's ask still wins over the linear ramp when it is longer. It just now
spends a budget while it waits.

## Compatibility

Breaking, deliberately — `v1` has one consumer today.

- `v1.ErrClosed` and `v1.ErrEdgeUnreachable` keep their names and keep
  answering `errors.Is`. Both change *type* from `error` (an `errors.New`
  value) to an `error`-typed `*class`, which is invisible to any caller using
  `errors.Is`. `ErrEdgeUnreachable`'s message text gains a `tunnel failed: `
  prefix; `ErrClosed`'s does not.
- `v1.ErrHostnameUnresolved` is removed. It has produced no error since
  readiness stopped polling DNS.
- `cloudflare.ErrMintRejected` and `cloudflare.ErrRateLimited` are removed,
  replaced by `v1.ErrRejected` and `v1.ErrRateLimited` in the stable package.
- `cloudflare.edgeTimeout` is removed; the edge path reads
  `v1.Budget(v1.ErrEdgeUnreachable)` instead. Same 30s, one home.
- The behavior change callers will actually notice: a mint that used to hang
  now fails, in at most 45s per failure class, rather than never.

## Testing

Real failures, not fabricated ones.

- **`v1/errors_test.go`** (new, package `v1_test`) — the `Is` relations and
  the budgets: every failure class answers `ErrFailed` and only itself;
  `ErrClosed` answers neither `ErrFailed` nor another class; `Budget` returns
  the class's value through arbitrary wrapping and zero for a non-class error.
- **`v1alpha1/errors_test.go`** (new, package `v1alpha1_test`) — a table
  driving `Classify` over errors produced by real operations, not fabricated
  ones: a plain `http.Client` against `httptest.NewTLSServer` (the untrusted
  cert), a lookup of a `.invalid` host (NXDOMAIN), a dial of a closed port
  (refused), a request to a URL with an unsupported scheme. Plus the
  idempotence case: an error already carrying a class comes back as it
  arrived.
- **`v1alpha1/cloudflare/cloudflare_test.go`** — the existing quick-tunnel
  tests live here (package `cloudflare`, internal), so the new cases join
  them rather than opening a `quicktunnel_test.go` the package does not have.
  Add: 429 with no rate-limit headers expiring its budget, 429 whose
  advertised reset exceeds the budget returning immediately with the duration
  in the message, and a persistent 500 returning `ErrProviderUnreachable`
  after its budget with the cause still wrapped. The expiry cases override the
  package's `budget` seam to milliseconds rather than sleeping through the
  real 45s.
- **Existing tests that must be updated, not deleted** —
  `TestExplicitHintRejectionStaysTerminal` (`:469`) and
  `TestQuickTunnelRejectionIsPermanent` (`:1137`) move from
  `ErrMintRejected` to `v1.ErrRejected`;
  `TestQuickTunnelSurfacesRateLimit` (`:1174`) moves to `v1.ErrRateLimited`
  and gains an assertion that its `Retry-After: 120` now returns immediately
  rather than riding out a 1500ms context;
  `TestEdgeUpWatcherCountsAttempts` (`:1238`) swaps `edgeTimeout` for
  `v1.Budget(v1.ErrEdgeUnreachable)`.

## Out of scope

The issue's fourth bullet — observing the first failure before the verdict,
via a callback or pollable state. Budgets cap the silent window at 45s per
failure class instead of indefinite, which is the actual complaint in the
report. A
progress callback is a separate API surface and earns its own issue if it is
still wanted afterwards.
