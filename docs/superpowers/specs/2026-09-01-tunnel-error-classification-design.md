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

One `Is` hierarchy, so `errors.Is(err, ErrFailed)` is the coarse "it will not
come up" check and the wrapping sentinel is the reason.

```go
// ErrFailed marks a tunnel that will not come up. Retrying will not help; the
// sentinel wrapping it says what an operator can do about it.
var ErrFailed = errors.New("tunnel failed")

// ErrCertificate is the Err result of a tunnel whose provider's certificate
// could not be verified — no trust store, a wrong system clock, or an
// intercepting proxy. No number of retries changes any of those.
var ErrCertificate = fmt.Errorf("%w: certificate verification", ErrFailed)

// ErrRejected is the Err result of a mint the provider definitively refused,
// or of a request libtunnel could not construct at all (a WithApiURL with a
// bad scheme or an invalid header).
var ErrRejected = fmt.Errorf("%w: rejected by the provider", ErrFailed)

// ErrUnreachable is the Err result of a provider host that does not resolve,
// refuses, times out or keeps 5xx-ing past its budget.
var ErrUnreachable = fmt.Errorf("%w: provider unreachable", ErrFailed)

// ErrRateLimited is the Err result of a mint rate limited past its budget, or
// rate limited with an advertised reset longer than that budget.
var ErrRateLimited = fmt.Errorf("%w: rate limited", ErrFailed)
```

`fmt.Errorf` with `%w` is what puts these in a hierarchy — `errors.Is(ErrCertificate, ErrFailed)`
is true — so no new exported type is needed, and Go 1.26 takes a second `%w`
for the underlying cause.

Two adjustments to what is already there:

- **`ErrEdgeUnreachable` folds in**, redefined as
  `fmt.Errorf("%w: edge unreachable", ErrFailed)`. `errors.Is(err, ErrEdgeUnreachable)`
  keeps working for existing callers; it now also answers `ErrFailed`, so "it
  will not come up" is one check across the mint and edge paths. Its message
  gains a `tunnel failed: ` prefix.
- **`ErrClosed` stays outside the hierarchy.** A deliberate close is not a
  failure. `ErrHostnameUnresolved` stays as the vestigial no-op it already is.

Removed: `cloudflare.ErrMintRejected` and `cloudflare.ErrRateLimited`
(`quicktunnel.go:24-32`). One vocabulary, in `v1`, not two.

### 2. The classifier — `v1alpha1/errors.go` (new file)

```go
// Classify names err with the v1 sentinel that describes it and says whether
// another attempt could plausibly change the answer. An error that already
// carries a sentinel — a provider naming a verdict only its protocol can read
// — is returned as it arrived; everything else is read at the transport
// level, which every backend shares.
func Classify(err error) (sentinel error, retry bool)
```

Rules, in order:

| condition | sentinel | retry |
|---|---|---|
| already carries a `v1` sentinel | that one, per the disposition table below | |
| `tls.CertificateVerificationError`, `x509.UnknownAuthorityError`, `x509.HostnameError`, `x509.CertificateInvalidError` | `ErrCertificate` | no |
| `*url.Error` from an unsupported scheme or an invalid header | `ErrRejected` | no |
| `*net.DNSError` with `IsNotFound` (NXDOMAIN) | `ErrUnreachable` | no |
| anything else — refused, timeout, transient DNS, 5xx | `ErrUnreachable` | yes |

Disposition by sentinel: `ErrCertificate` no, `ErrRejected` no,
`ErrRateLimited` yes, `ErrUnreachable` yes, `ErrEdgeUnreachable` yes.

**Provider classifiers fold in by construction, not by a second function.**
Cloudflare gets no `classify` of its own. `fetch` already knows the two
verdicts only the quick-tunnel protocol can read, so it names them at the
source — `v1.ErrRejected` for `success=false` under HTTP 500,
`v1.ErrRateLimited` for 429 — and returns everything else raw. `Classify`
recognizes the named ones by rule 1 and reads the rest. A future backend
needing protocol-level naming does the same: tag at the source, and let
`Classify` stay the only place a disposition is decided.

`Classify` is therefore also where `ErrEdgeUnreachable` gets its disposition,
so the edge path and the mint path answer one function.

### 3. Budgets — same file

The classifier's other half: how long a retryable class may keep failing
before its sentinel becomes the verdict.

```go
// Budget is how long a retryable class may keep failing before its sentinel
// becomes the verdict. Each class carries its own clock — it runs only while
// the loop is failing that way, so a mint that hits a rate limit and then a
// flaky resolver is not charged twice for one slow start. Non-retryable
// classes return 0.
func Budget(sentinel error) time.Duration
```

- `ErrRateLimited` — **2 minutes**. A provider advertising a reset longer than
  this is reported now rather than waited out: the caller can act on "rate
  limited, resets in 5m" immediately, and `quicktunnel.go:185-196` already
  parses that duration, so it goes straight into the message.
- `ErrUnreachable` — **30 seconds**. The mint-side twin of `edgeTimeout`
  (`cloudflare.go:876`), and deliberately the same number: a container that
  starts before its resolver is ready recovers inside it; a typo'd provider
  host never does, and stops looking like a slow one.
- Everything else — 0.

Package consts, no env knob, mirroring how `edgeTimeout` is expressed.
`Budget` itself is a plain function over them, so it is directly testable.

The retry loop reaches it through an unexported package var in
`quicktunnel.go` — `var budget = v1alpha1.Budget` — which is the loop's test
seam, following the one `cloudflare_test.go:995` already establishes for the
API URL. That keeps `v1alpha1.Budget` a clean function rather than a mutable
exported var, and lets an internal test drive the loop to expiry in
milliseconds instead of 30 seconds.

### 4. The retry loop — `v1alpha1/cloudflare/quicktunnel.go`

The loop at `228-265` consults `Classify` on every error, at arrival, before
deciding to go round again:

```go
sentinel, retry := v1alpha1.Classify(err)
if !retry {
    return nil, fmt.Errorf("%w: %w", sentinel, err)
}
spent[sentinel] += wait
if spent[sentinel] > v1alpha1.Budget(sentinel) {
    return nil, fmt.Errorf("%w: no spec after %d attempts in %s: %w",
        sentinel, attempts, spent[sentinel], err)
}
```

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

- `errors.Is(err, v1.ErrEdgeUnreachable)` and `errors.Is(err, v1.ErrClosed)`
  keep working. `ErrEdgeUnreachable`'s *message text* gains a prefix.
- `cloudflare.ErrMintRejected` and `cloudflare.ErrRateLimited` are removed.
  Both are in `v1alpha1`, which `v1/v1.go` documents as changeable between
  alpha revisions; `v1.ErrRejected` and `v1.ErrRateLimited` replace them, in
  the stable package.
- The behavior change callers will actually notice: a mint that used to hang
  now fails, in at most 30s (or 2m against a rate limit) rather than never.

## Testing

Real failures, not fabricated ones.

- **`v1alpha1/errors_test.go`** — a table driving `Classify` over errors
  produced by real operations: a client against `httptest.NewTLSServer` (the
  untrusted-cert path), a lookup of a `.invalid` host (NXDOMAIN), a dial of a
  closed port (refused), a request to a `WithApiURL` with a bad scheme. Plus
  the idempotence case: a pre-named sentinel comes back unchanged with the
  right disposition.
- **`v1alpha1/cloudflare/quicktunnel_test.go`** — an `httptest` handler
  returning 429 with `Retry-After`, 429 with the reset headers, 429 with
  neither, `success=false` under 500, and a persistent 500. Assert the
  sentinel, that non-retryables return on the first attempt, that the
  persistent 500 returns `ErrUnreachable` after its budget with the cause
  still wrapped, and that the reclaim path still drops hints and retries once.
  The expiry cases override the package's `budget` seam to milliseconds rather
  than sleeping through the real 30s and 2m.
- **`v1/v1_test.go`** — the `Is` hierarchy: every failure sentinel answers
  `ErrFailed`; `ErrClosed` does not.

## Out of scope

The issue's fourth bullet — observing the first failure before the verdict,
via a callback or pollable state. Budgets cap the silent window at 30s / 2m
instead of indefinite, which is the actual complaint in the report. A
progress callback is a separate API surface and earns its own issue if it is
still wanted afterwards.
