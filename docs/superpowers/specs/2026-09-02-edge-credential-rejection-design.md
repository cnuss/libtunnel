# Failing fast on a credential the edge refuses

Design for [#170](https://github.com/cnuss/libtunnel/issues/170).

## Problem

A spec whose tunnel no longer exists fails as `ErrEdgeUnreachable`, thirty
seconds later, with advice about UDP egress that cannot possibly help:

```
tunnel failed: edge unreachable: no connection after 5 attempts in 30s:
your machine/network is getting its egress UDP to port 7844 (or others)
blocked or dropped. …
```

The network is fine. The edge said exactly what was wrong —
`Unauthorized: Tunnel not found` — and it reached the caller as a debug
record, invisible to anyone not already running at debug.

Two defects produce that:

1. **`slogWriter.Write` forwards every cloudflared line as `log.Debug`**,
   whatever level the JSON it just serialized carries. An `error` the edge
   reported explicitly is invisible at `--log-level=error`, which is the level
   where someone is asking for exactly this.
2. **`edgeBlockedHint` is attached to every expiry of the edge budget.** It is
   cloudflared's diagnosis of *protocol selection* failing. A rejected
   credential and a dropped UDP port produce the same sentence.

## What the investigation settled

The issue asks whether cloudflared surfaces this as a typed error worth
plumbing instead of matching a string. It does not, at any layer:

| layer | what it offers |
| --- | --- |
| `connection.Event` (the observer sink `edgeUpWatcher` already taps) | `Index`, `EventType`, `Location`, `Protocol`, `URL`, `EdgeAddress` — **no error** |
| `Supervisor.Run` | returns `nil` on every path; a tunnel error is logged as `"Connection terminated"` and never returned |
| `TunnelConfig.Retries` | cannot help — all three `retry.NewBackoff` sites pass `retryForever=true` hardcoded, so `GetMaxBackoffDuration` only returns false on `ctx.Done()` |
| cloudflared itself | `strings.Contains(err.Error(), "Unauthorized")` in `supervisor.startFirstTunnel` |

So the log bridge is the only channel that carries the reason, and a string
match is what upstream does *with the error value in hand*. libtunnel cannot do
better than the library it wraps.

Two further facts worth recording:

- **The retry is deliberate upstream.** `startFirstTunnel` retries
  `Unauthorized` forever because it hopes it is "transient due to edge
  propagation lag on new Tunnels". Correct for a fresh mint; never-terminating
  for a reaped one. libtunnel's 30s budget always wins that race, which is why
  the timeout is what the caller sees.
- **The message is Cloudflare's, not the mint provider's.**
  `Unauthorized: Tunnel not found` appears nowhere in cloudflared's source; it
  arrives from the edge over the control stream
  (`ServeControlStream` → `c.controlStreamErr`, logged at
  `connection/http2.go:158`). The mint API is not consulted on the replay path
  at all, so nothing it could say about its own errors would change this.

## Design

### 1. Level mapping without paying on the hot path — `v1alpha1/cloudflare/zerolog.go`

`zerologger` returns `zerolog.Nop()` unless the slog handler accepts Debug.
That skips cloudflared's per-event JSON serialization, which sits on the proxy
hot path — a real optimization — but it throws away warnings and errors to get
it.

Set zerolog's own threshold from the handler instead, so the same events are
skipped without the same collateral:

```go
func zerologger(log *slog.Logger, reject *edgeReject) *zerolog.Logger {
	lvl := zerolog.WarnLevel
	if log.Enabled(context.Background(), slog.LevelDebug) {
		lvl = zerolog.DebugLevel
	}
	l := zerolog.New(slogWriter{log: log, reject: reject}).
		Level(lvl).
		With().Str("component", "tunnel").Logger()
	return &l
}
```

zerolog drops a sub-threshold event before serializing it, so the hot path
stays exactly as cheap as today. `Write` then reads the level out of the JSON
and forwards at the matching slog level. zerolog writes `level` as the first
field, so this is a prefix scan rather than an unmarshal:

```go
// zerolog emits {"level":"error",...} with level first — confirmed by the
// record in #170 — so the value is the span between the third quote and the
// fourth. A line that does not match that shape (a non-JSON writer, a future
// zerolog) forwards at debug, as every line does today.
func recordLevel(p []byte) slog.Level
```

**Consequence to expect:** cloudflared warnings and errors now surface at the
default level. That is the defect being fixed, and it is more output than
today.

### 2. Detecting the refusal

An `edgeReject` on the `Backend`, holding a once-guarded channel and the edge's
own message:

```go
// edgeReject records the first registration refusal the edge reports, so
// connect can fail on it rather than waiting out the budget for a credential
// no retry will fix.
type edgeReject struct {
	once sync.Once
	ch   chan struct{}
	msg  string // written inside once.Do before ch closes; read only after
}

func (r *edgeReject) fire(msg string)     // once: record msg, then close ch
func (r *edgeReject) wait() <-chan struct{}
func (r *edgeReject) message() string
```

No mutex or atomic on `msg`: it is written inside `once.Do` before `close(ch)`,
and every reader reaches it through a receive on `ch`, so the channel supplies
the happens-before. The race detector covers this in the CI race lane.

The value is created in `connect`, beside `b.reconnected` and `b.edgeUp`
(`cloudflare.go:682-683`) — the block the struct already labels "runtime state
wired at connect". One per backend is right: `libtunnel.Cloudflare()` hands out
a fresh backend per tunnel, and `connect` runs once for it.

`slogWriter` holds a pointer to it and fires on an error-level record
containing `Unauthorized`, capturing the record's `error` field as the message.

**On the looseness of that match.** A proxied origin returning 401 could in
principle also contain the word. Two things bound it: the sink only arms before
the first successful connection (after that, `connect` has returned and nothing
reads the channel), and it is the identical test cloudflared applies to the
error value it holds directly. This is documented at the call site rather than
hidden — there is no better signal, which the table above establishes.

### 3. `ErrCredentialRejected` — `v1/v1.go`

```go
// ErrCredentialRejected is the Err result of a tunnel whose credentials the
// edge refused: the spec names a tunnel that no longer exists, or was never
// this caller's. Distinct from ErrRejected, which is a provider declining to
// mint — the recoveries differ, and only this one means "the spec you replayed
// is dead, discard it".
ErrCredentialRejected error = &class{ErrFailed, "credential rejected by the edge", 0}
```

Budget 0, so `Classify` reports it as terminal by construction, exactly as
`ErrCertificate` and `ErrRejected` already are.

### 4. `connect` — `v1alpha1/cloudflare/cloudflare.go:863-875`

A fourth select case:

```go
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connected.Wait():
	case <-b.edgeReject.wait():
		return fmt.Errorf("%w: %s", v1.ErrCredentialRejected, b.edgeReject.message())
	case <-timeout.C:
		return fmt.Errorf("%w: no connection after %d attempts in %s: %s",
			v1.ErrEdgeUnreachable, b.edgeUp.attemptCount(), edgeBudget, edgeBlockedHint)
	}
```

**The hint needs no condition.** A refusal now leaves through its own case, so
`edgeBlockedHint` is reached only on a genuine timeout with no refusal seen —
accurate by elimination. Its comment does need updating: it currently justifies
itself by saying cloudflared logs the diagnosis "at warn level — where the
tunnel's logger is silent by default (see zerologger) and it is never seen",
and §1 makes that untrue.

## Testing

The bridge holds the logic and is fully testable in-package:

- **Level mapping** — feed `slogWriter` real zerolog output at each level and
  assert the slog record comes out at the matching level; assert a malformed
  line still forwards at debug.
- **Threshold** — assert `zerologger` yields a Warn-level logger for an
  info-level handler and a Debug-level one for a debug handler, so the hot-path
  skip survives.
- **Refusal detection** — feed the real record from the issue and assert the
  channel fires and `message()` returns the edge's text; assert a debug-level
  line carrying the same word does not fire.
- **The class** — extend `v1/errors_test.go`'s table: `ErrCredentialRejected`
  answers `ErrFailed`, answers no other class, and has budget 0.

**Not covered, stated rather than papered over:** `connect`'s select needs a
live edge, and the failure itself needs a reaped tunnel's spec, which cannot be
arranged deterministically. The offline tests pin the mechanism; the real
confirmation is tunneld's next replay of a stale spec.

## Downstream

tunneld can then key its recovery on `ErrCredentialRejected`: discard the
cached spec and mint fresh. That is the actual repair, and it is not a decision
it can make on `ErrEdgeUnreachable`.

## Out of scope

An endpoint that answers "is this spec still alive?" before anything dials the
edge. That would turn a 30-second discovery into one cheap round trip, and it
is the same server-side probe #168's followup defers — it belongs there, with
the reclaim question, not here.
