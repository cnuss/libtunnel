# Edge Credential Rejection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Report a credential the edge refuses as a terminal `ErrCredentialRejected` carrying the edge's own words, immediately, instead of as a 30-second timeout blaming the firewall.

**Architecture:** cloudflared exposes no typed error for this at any layer, so the log bridge is the only channel that carries the reason. Give zerolog a real level threshold instead of disabling it outright, map each record's level onto slog, and have the bridge fire a one-shot signal when it sees the edge refuse a registration. `connect` selects on that signal alongside its existing budget timer.

**Tech Stack:** Go 1.26, `log/slog`, `github.com/rs/zerolog`, stdlib `bytes`/`sync`.

**Spec:** `docs/superpowers/specs/2026-09-02-edge-credential-rejection-design.md`

## Global Constraints

- Go 1.26 or later. Module `github.com/cnuss/libtunnel`.
- Import alias for the stable package is `v1 "github.com/cnuss/libtunnel/v1"` — match the existing files.
- Every exported identifier gets a godoc comment. Existing comments explain *why*, not *what*; match that register.
- Do not write comments narrating what was removed or referencing an issue number for behavior that is absent. Comments describe what the code does.
- No new dependencies. `v1` must not import `v1alpha1`.
- Before each commit: `gofmt -w .` then `go vet ./...`.
- `make test` is the fast tier (`-short`) and must pass at the end of every task. `make race` matters here — the new type is shared across goroutines. `make e2e` mints real tunnels; run it once at the end.
- The README mirrors the public surface (CONTRIBUTING's rule): a new exported sentinel means the README's failure-class table changes in the same PR.

---

### Task 1: `ErrCredentialRejected`

**Files:**
- Modify: `v1/v1.go` (the failure-class `var` block, ends `:115`)
- Modify: `lib.go` (the façade's re-export block)
- Test: `v1/errors_test.go`

**Interfaces:**
- Consumes: the existing `class` type and `ErrFailed` in `v1/v1.go`.
- Produces: `v1.ErrCredentialRejected error` and `libtunnel.ErrCredentialRejected`, budget 0.

- [ ] **Step 1: Extend the existing test tables**

`v1/errors_test.go` has three tables that enumerate the classes. Add the new one to each.

In `TestFailureClassesAnswerErrFailed`:

```go
	classes := []error{
		v1.ErrCertificate,
		v1.ErrRejected,
		v1.ErrCredentialRejected,
		v1.ErrProviderUnreachable,
		v1.ErrEdgeUnreachable,
		v1.ErrRateLimited,
	}
```

In `TestBudgets`, add a row:

```go
		{v1.ErrCredentialRejected, 0},
```

And append a test pinning the distinction that motivates a separate class:

```go
// TestCredentialRejectionIsItsOwnClass pins that an edge-refused credential is
// distinguishable from a provider-refused mint. A caller replaying a spec acts
// on the first by discarding it; that is the wrong move for the second.
func TestCredentialRejectionIsItsOwnClass(t *testing.T) {
	if errors.Is(v1.ErrCredentialRejected, v1.ErrRejected) {
		t.Error("errors.Is(ErrCredentialRejected, ErrRejected) = true, want false")
	}
	if errors.Is(v1.ErrRejected, v1.ErrCredentialRejected) {
		t.Error("errors.Is(ErrRejected, ErrCredentialRejected) = true, want false")
	}
	if got, want := v1.ErrCredentialRejected.Error(), "tunnel failed: credential rejected by the edge"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./v1/ -run 'TestFailureClasses|TestBudgets|TestCredentialRejection' -v`

Expected: FAIL to build — `undefined: v1.ErrCredentialRejected`.

- [ ] **Step 3: Add the class**

In `v1/v1.go`, inside the failure-class `var` block, after `ErrRejected`:

```go
	// ErrCredentialRejected is the Err result of a tunnel whose credentials
	// the edge refused: the spec names a tunnel that no longer exists, or was
	// never this caller's. Distinct from ErrRejected, which is a provider
	// declining to mint — the recoveries differ, and only this one means the
	// spec that was replayed is dead and should be discarded.
	ErrCredentialRejected error = &class{ErrFailed, "credential rejected by the edge", 0}
```

- [ ] **Step 4: Re-export it on the façade**

In `lib.go`, add to the failure-class `var` block, keeping the column alignment `gofmt` will enforce:

```go
	ErrCredentialRejected  = v1.ErrCredentialRejected  // the edge refused these credentials
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./v1/ ./ -count=1`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w . && go vet ./...
git add v1/v1.go lib.go v1/errors_test.go
git commit -m "feat: add ErrCredentialRejected for an edge-refused credential

A spec naming a tunnel that no longer exists needs a class of its own: the
recovery is to discard the spec and mint fresh, which is wrong for ErrRejected,
where a provider declined to mint a new tunnel in the first place.

Refs #170"
```

---

### Task 2: Map cloudflared's log levels onto slog

**Files:**
- Modify: `v1alpha1/cloudflare/zerolog.go`
- Test: `v1alpha1/cloudflare/zerolog_test.go` (create)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `func recordLevel(p []byte) slog.Level`; `slogWriter` forwards at the record's own level; `zerologger(log *slog.Logger) *zerolog.Logger` keeps its signature in this task and gains a threshold instead of returning `Nop()`.

- [ ] **Step 1: Write the failing test**

Create `v1alpha1/cloudflare/zerolog_test.go`:

```go
package cloudflare

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// capture is a slog handler that records the level and message of every
// record it accepts, at every level, so a test can assert what the bridge
// forwarded rather than what it was handed.
type capture struct {
	levels []slog.Level
	msgs   []string
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.levels = append(c.levels, r.Level)
	c.msgs = append(c.msgs, r.Message)
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

// TestRecordLevelReadsZerologLevel pins the parse. zerolog writes level as the
// first field, so the bridge reads it off the prefix instead of decoding the
// record — this sits on the proxy hot path.
func TestRecordLevelReadsZerologLevel(t *testing.T) {
	for _, tc := range []struct {
		line string
		want slog.Level
	}{
		{`{"level":"error","component":"tunnel","message":"boom"}`, slog.LevelError},
		{`{"level":"fatal","message":"boom"}`, slog.LevelError},
		{`{"level":"panic","message":"boom"}`, slog.LevelError},
		{`{"level":"warn","message":"careful"}`, slog.LevelWarn},
		{`{"level":"info","message":"hello"}`, slog.LevelInfo},
		{`{"level":"debug","message":"detail"}`, slog.LevelDebug},
		{`{"level":"trace","message":"detail"}`, slog.LevelDebug},
		{`not json at all`, slog.LevelDebug},
		{`{"message":"no level field"}`, slog.LevelDebug},
		{`{"level":"unterminated`, slog.LevelDebug},
	} {
		if got := recordLevel([]byte(tc.line)); got != tc.want {
			t.Errorf("recordLevel(%s) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// TestSlogWriterForwardsAtRecordLevel pins the fix for the collapse: an error
// cloudflared reported explicitly must reach a caller running at error level,
// which is exactly where they are asking for it.
func TestSlogWriterForwardsAtRecordLevel(t *testing.T) {
	c := &capture{}
	w := slogWriter{log: slog.New(c)}

	line := `{"level":"error","component":"tunnel","error":"Unauthorized: Tunnel not found","message":"failed to serve incoming request"}`
	if _, err := w.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	if len(c.levels) != 1 {
		t.Fatalf("wrote %d records, want 1", len(c.levels))
	}
	if c.levels[0] != slog.LevelError {
		t.Errorf("forwarded at %v, want %v", c.levels[0], slog.LevelError)
	}
	if !strings.Contains(c.msgs[0], "Unauthorized: Tunnel not found") {
		t.Errorf("message = %q, want the record verbatim", c.msgs[0])
	}
	if strings.HasSuffix(c.msgs[0], "\n") {
		t.Error("trailing newline was not trimmed")
	}
}

// TestZerologgerThreshold pins the hot-path skip. zerolog drops a
// sub-threshold event before serializing it, so a silent tunnel must still get
// a logger that refuses debug and info — otherwise every proxied request pays
// for JSON nobody reads.
func TestZerologgerThreshold(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if got := zerologger(quiet).GetLevel(); got != zerolog.WarnLevel {
		t.Errorf("info-level handler yields zerolog %v, want %v", got, zerolog.WarnLevel)
	}
	loud := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if got := zerologger(loud).GetLevel(); got != zerolog.DebugLevel {
		t.Errorf("debug-level handler yields zerolog %v, want %v", got, zerolog.DebugLevel)
	}
}
```

Add `"io"` to that file's imports — `TestZerologgerThreshold` needs it.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./v1alpha1/cloudflare/ -run 'TestRecordLevel|TestSlogWriter|TestZerologgerThreshold' -v`

Expected: FAIL to build — `undefined: recordLevel`. `TestZerologgerThreshold` will also fail once it compiles, because `zerologger` currently returns a `Nop()` logger (level `Disabled`) for the quiet handler.

- [ ] **Step 3: Write the implementation**

Replace the body of `v1alpha1/cloudflare/zerolog.go` below the imports with:

```go
// slogWriter adapts zerolog's io.Writer sink onto slog so cloudflared tunnel
// logs surface through the tunnel's configured logger instead of being
// discarded. zerolog accepts any io.Writer; slog has no matching ingress
// writer, so each emitted line is forwarded as a record at the level the line
// itself carries.
type slogWriter struct {
	log *slog.Logger
}

var _ io.Writer = slogWriter{}

func (w slogWriter) Write(p []byte) (int, error) {
	w.log.Log(context.Background(), recordLevel(p), strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// recordLevel reads the level off a zerolog record. zerolog writes level as
// the record's first field, so this is a prefix scan rather than a decode —
// the bridge sits on the proxy hot path and every line goes through it.
// Anything that does not match that shape reads as debug, which is how every
// line was treated before.
func recordLevel(p []byte) slog.Level {
	const prefix = `{"level":"`
	if !bytes.HasPrefix(p, []byte(prefix)) {
		return slog.LevelDebug
	}
	rest := p[len(prefix):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return slog.LevelDebug
	}
	switch string(rest[:end]) {
	case "error", "fatal", "panic":
		return slog.LevelError
	case "warn":
		return slog.LevelWarn
	case "info":
		return slog.LevelInfo
	default:
		return slog.LevelDebug
	}
}

// zerologger bridges the tunnel's slog.Logger into the *zerolog.Logger
// cloudflared's plumbing requires, with zerolog's own level set from the
// handler. zerolog drops a sub-threshold event before serializing it, so a
// silent tunnel still skips the per-event JSON encoding that sits on the proxy
// hot path — while warnings and errors, which a caller at any level wants,
// still get through.
func zerologger(log *slog.Logger) *zerolog.Logger {
	lvl := zerolog.WarnLevel
	if log.Enabled(context.Background(), slog.LevelDebug) {
		lvl = zerolog.DebugLevel
	}
	l := zerolog.New(slogWriter{log: log}).Level(lvl).With().Str("component", "tunnel").Logger()
	return &l
}
```

Add `"bytes"` to the file's imports.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./v1alpha1/cloudflare/ -run 'TestRecordLevel|TestSlogWriter|TestZerologgerThreshold' -v`

Expected: PASS, all three.

- [ ] **Step 5: Run the package suite**

Run: `go test ./v1alpha1/cloudflare/ -short -count=1`

Expected: PASS. Nothing else asserts on log output, but this is the package where the change lands.

- [ ] **Step 6: Commit**

```bash
gofmt -w . && go vet ./...
git add v1alpha1/cloudflare/zerolog.go v1alpha1/cloudflare/zerolog_test.go
git commit -m "fix: forward cloudflared logs at the level they carry

The bridge forwarded every line as debug, so an error the edge reported
explicitly was invisible at --log-level=error, which is where a caller is
asking for exactly that. It also returned a disabled logger below debug, which
threw away warnings and errors to skip per-event JSON on the proxy hot path.

Setting zerolog's own threshold from the handler keeps that skip — zerolog
drops a sub-threshold event before serializing — without the collateral.

Refs #170"
```

---

### Task 3: Detect the edge's refusal in the bridge

**Files:**
- Modify: `v1alpha1/cloudflare/zerolog.go`
- Modify: `v1alpha1/cloudflare/cloudflare.go` — the `Backend` runtime-state fields (`:157-166`), the wiring at `:682-683`, the `zerologger` call at `:697`
- Test: `v1alpha1/cloudflare/zerolog_test.go`

**Interfaces:**
- Consumes: `recordLevel` from Task 2.
- Produces: `type edgeReject`, `func newEdgeReject() *edgeReject`, methods `fire(msg string)`, `wait() <-chan struct{}`, `message() string`; `slogWriter` gains a `reject *edgeReject` field; `zerologger(log *slog.Logger, reject *edgeReject) *zerolog.Logger`; `b.edgeReject` live from `connect`.

`zerologger`'s signature changes, so its one call site changes in this task
too — a task that left the package uncompilable for the next one would not be
independently reviewable, and its commit would not build.

- [ ] **Step 1: Write the failing test**

Append to `v1alpha1/cloudflare/zerolog_test.go`:

```go
// TestEdgeRejectFiresOnRefusal pins the detection. The record is the one from
// #170, verbatim: the edge refusing a replayed spec whose tunnel was reaped.
func TestEdgeRejectFiresOnRefusal(t *testing.T) {
	r := newEdgeReject()
	w := slogWriter{log: slog.New(&capture{}), reject: r}

	line := `{"level":"error","component":"tunnel","error":"Unauthorized: Tunnel not found","message":"failed to serve incoming request"}`
	if _, err := w.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.wait():
	default:
		t.Fatal("the refusal did not fire")
	}
	if got, want := r.message(), "Unauthorized: Tunnel not found"; got != want {
		t.Errorf("message() = %q, want the edge's own text %q", got, want)
	}
}

// TestEdgeRejectIgnoresNonRefusals pins what must NOT fire: the match is
// scoped to an error-level record carrying an error field that names the
// refusal, so ordinary traffic cannot strand a working tunnel.
func TestEdgeRejectIgnoresNonRefusals(t *testing.T) {
	for _, line := range []string{
		`{"level":"debug","component":"tunnel","error":"Unauthorized: Tunnel not found","message":"noise"}`,
		`{"level":"error","component":"tunnel","error":"Failed to proxy HTTP: 503","message":"failed to serve incoming request"}`,
		`{"level":"error","component":"tunnel","message":"no error field"}`,
		`{"level":"info","component":"tunnel","message":"Registered tunnel connection"}`,
	} {
		r := newEdgeReject()
		w := slogWriter{log: slog.New(&capture{}), reject: r}
		if _, err := w.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-r.wait():
			t.Errorf("fired on a record that is not a refusal: %s", line)
		default:
		}
	}
}

// TestEdgeRejectFiresOnce pins the once-guard: the edge refuses every retry,
// and a second close would panic.
func TestEdgeRejectFiresOnce(t *testing.T) {
	r := newEdgeReject()
	r.fire("first")
	r.fire("second")
	if got := r.message(); got != "first" {
		t.Errorf("message() = %q, want the first refusal", got)
	}
}

// TestSlogWriterWithoutRejectSink pins that the sink is optional — the bridge
// is constructed without one in tests and must not panic.
func TestSlogWriterWithoutRejectSink(t *testing.T) {
	w := slogWriter{log: slog.New(&capture{})}
	line := `{"level":"error","error":"Unauthorized: Tunnel not found","message":"boom"}`
	if _, err := w.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./v1alpha1/cloudflare/ -run TestEdgeReject -v`

Expected: FAIL to build — `undefined: newEdgeReject`, and `unknown field reject in struct literal`.

- [ ] **Step 3: Write the implementation**

Add to `v1alpha1/cloudflare/zerolog.go`:

```go
// edgeReject records the first registration refusal the edge reports, so
// connect can fail on it rather than waiting out the edge budget for a
// credential no retry will fix. cloudflared retries an Unauthorized forever by
// design — it hopes the condition is edge propagation lag on a new tunnel —
// which is right for a fresh mint and never terminates for a reaped one.
//
// msg is written inside once.Do before ch closes, and every reader reaches it
// through a receive on ch, so the channel supplies the happens-before.
type edgeReject struct {
	once sync.Once
	ch   chan struct{}
	msg  string
}

func newEdgeReject() *edgeReject { return &edgeReject{ch: make(chan struct{})} }

func (r *edgeReject) fire(msg string) {
	r.once.Do(func() {
		r.msg = msg
		close(r.ch)
	})
}

// wait closes when the edge has refused the tunnel's credentials.
func (r *edgeReject) wait() <-chan struct{} { return r.ch }

// message is the edge's own words, valid once wait has closed.
func (r *edgeReject) message() string { return r.msg }

// edgeRefusal reports whether an error-level record carries the edge refusing
// the tunnel's credentials, and the message it gave.
//
// Matching a string is not a choice so much as the only option: cloudflared
// exposes no typed error for this at any layer — connection.Event carries no
// error, Supervisor.Run returns nil on every path, and upstream itself tests
// strings.Contains(err.Error(), "Unauthorized") on the value it holds
// directly. The scope is what keeps it honest: the sink is only read before
// the first connection succeeds, so a later 401 proxied from an origin has
// nothing listening.
func edgeRefusal(p []byte) (string, bool) {
	const key = `"error":"`
	i := bytes.Index(p, []byte(key))
	if i < 0 {
		return "", false
	}
	rest := p[i+len(key):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return "", false
	}
	msg := string(rest[:end])
	if !strings.Contains(msg, "Unauthorized") {
		return "", false
	}
	return msg, true
}
```

Add `"sync"` to the imports. Then give `slogWriter` the sink and consult it:

```go
type slogWriter struct {
	log    *slog.Logger
	reject *edgeReject
}

func (w slogWriter) Write(p []byte) (int, error) {
	lvl := recordLevel(p)
	if lvl >= slog.LevelError && w.reject != nil {
		if msg, ok := edgeRefusal(p); ok {
			w.reject.fire(msg)
		}
	}
	w.log.Log(context.Background(), lvl, strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
```

And thread it through the constructor:

```go
func zerologger(log *slog.Logger, reject *edgeReject) *zerolog.Logger {
	lvl := zerolog.WarnLevel
	if log.Enabled(context.Background(), slog.LevelDebug) {
		lvl = zerolog.DebugLevel
	}
	l := zerolog.New(slogWriter{log: log, reject: reject}).Level(lvl).With().Str("component", "tunnel").Logger()
	return &l
}
```

- [ ] **Step 4: Fix the Task 2 test for the new signature**

`TestZerologgerThreshold` now calls a two-argument function. Pass `nil` for the sink in both calls: `zerologger(quiet, nil)` and `zerologger(loud, nil)`.

- [ ] **Step 5: Wire the sink through the backend**

The signature change breaks `cloudflare.go:697`, so the call site moves in this
task. Add the field to `Backend`'s runtime-state block (`cloudflare.go:157-166`), after `edgeUp`:

```go
	// edgeReject carries the edge's refusal of these credentials from the log
	// bridge to connect, which fails on it instead of waiting out the budget.
	edgeReject *edgeReject
```

Extend the block comment above those fields so `edgeReject` is covered: it currently reads "reconnected feeds the supervisor's external-control channel, edgeUp tracks edge connections". Make it "reconnected feeds the supervisor's external-control channel, edgeUp tracks edge connections, edgeReject carries a refused registration back from the log bridge".

Initialize it beside the others at `cloudflare.go:682-683`:

```go
	b.reconnected = make(chan supervisor.ReconnectSignal)
	b.edgeUp = newEdgeUpWatcher()
	b.edgeReject = newEdgeReject()
```

Pass it to the bridge at `cloudflare.go:697`:

```go
	log := zerologger(t.Logger(), b.edgeReject)
```

Nothing reads `b.edgeReject.wait()` yet — Task 4 adds that. The sink is armed
and inert, which is a complete, compiling, reviewable state.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./v1alpha1/cloudflare/ -count=1 -short -race`

Expected: PASS, whole package. `-race` matters — `edgeReject` is written by the bridge's goroutine and read by `connect`'s.

- [ ] **Step 7: Commit**

```bash
gofmt -w . && go vet ./...
git add v1alpha1/cloudflare/zerolog.go v1alpha1/cloudflare/zerolog_test.go v1alpha1/cloudflare/cloudflare.go
git commit -m "feat: detect the edge refusing a tunnel's credentials

cloudflared exposes no typed error for a refused registration: the observer's
Event carries none, Supervisor.Run returns nil on every path, and upstream
itself matches strings.Contains(err.Error(), \"Unauthorized\") on the value it
holds directly. The log bridge is the only channel that carries the reason.

edgeReject is a one-shot signal the bridge fires when it sees that refusal, so
a caller can be told the credential is dead instead of waiting out a budget.

Refs #170"
```

---

### Task 4: Fail `connect` on the refusal

**Files:**
- Modify: `v1alpha1/cloudflare/cloudflare.go` — the select at `:867-874` and `edgeBlockedHint`'s comment at `:878-882`
- Test: `v1alpha1/cloudflare/cloudflare_test.go`

**Interfaces:**
- Consumes: `b.edgeReject` (live from Task 3), `edgeReject.wait()`, `edgeReject.message()`; `v1.ErrCredentialRejected` from Task 1.
- Produces: `connect` returns an error wrapping `v1.ErrCredentialRejected` when the edge refuses.

- [ ] **Step 1: Write the failing test**

Append to `v1alpha1/cloudflare/cloudflare_test.go`:

```go
// TestEdgeRejectionBeatsTheBudget pins the shape of the failure a caller sees.
// connect's select cannot be driven without a live edge, so this asserts the
// error the refusal branch constructs: the class, the umbrella, the edge's own
// words, and — the point of the fix — no firewall advice.
func TestEdgeRejectionBeatsTheBudget(t *testing.T) {
	r := newEdgeReject()
	r.fire("Unauthorized: Tunnel not found")

	err := fmt.Errorf("%w: %s", v1.ErrCredentialRejected, r.message())

	if !errors.Is(err, v1.ErrCredentialRejected) {
		t.Errorf("err = %v, want errors.Is(_, ErrCredentialRejected)", err)
	}
	if !errors.Is(err, v1.ErrFailed) {
		t.Errorf("err = %v, want errors.Is(_, ErrFailed)", err)
	}
	if errors.Is(err, v1.ErrEdgeUnreachable) {
		t.Error("a refused credential must not read as an unreachable edge")
	}
	if !strings.Contains(err.Error(), "Unauthorized: Tunnel not found") {
		t.Errorf("err = %v, want the edge's own message", err)
	}
	if strings.Contains(err.Error(), "egress") {
		t.Errorf("err = %v, want no firewall advice on a credential failure", err)
	}
	if v1.Budget(err) != 0 {
		t.Errorf("Budget = %s, want 0 (a dead credential is never retried)", v1.Budget(err))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./v1alpha1/cloudflare/ -run TestEdgeRejectionBeatsTheBudget -v`

Expected: FAIL to build — `undefined: v1.ErrCredentialRejected` if Task 1 is not yet applied. With Tasks 1 and 3 done it compiles and fails on the assertions, since nothing constructs that error yet.

- [ ] **Step 3: Add the select case**

At `cloudflare.go:867-874`, add the refusal branch before the timeout:

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

- [ ] **Step 4: Correct `edgeBlockedHint`'s comment**

At `cloudflare.go:878-882` the comment justifies copying the hint by saying cloudflared logs its diagnosis "at warn level — where the tunnel's logger is silent by default (see zerologger) and it is never seen". Task 2 made that untrue. Replace that clause:

```go
// edgeBlockedHint is cloudflared's own diagnosis of this failure, which it logs
// at warn level from selectNextProtocol. Repeated verbatim so the error carries
// the same guidance without the caller having to correlate it with a log line,
// plus libtunnel's way around it.
//
// It rides only the timeout branch. A credential the edge refuses leaves
// through its own case above, so reaching this means nothing better is known
// about why the edge never answered.
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./v1alpha1/cloudflare/ -count=1 -short -race`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
gofmt -w . && go vet ./...
git add v1alpha1/cloudflare/cloudflare.go v1alpha1/cloudflare/cloudflare_test.go
git commit -m "fix: fail immediately on a credential the edge refuses

connect waited out its 30s edge budget and then reported ErrEdgeUnreachable
with advice about UDP egress, for a spec whose tunnel had been reaped. The
network was fine and no amount of opening ports would have helped.

The refusal now leaves through its own select case as ErrCredentialRejected,
carrying the edge's own words. The firewall hint stays on the timeout branch,
where it is now accurate by elimination.

Refs #170"
```

---

### Task 5: Document the class

**Files:**
- Modify: `v1/v1.go` — the `Tunnel.Err` godoc
- Modify: `README.md` — the failure-class table and the `switch` example

**Interfaces:**
- Consumes: `v1.ErrCredentialRejected` from Task 1. Produces no code.

- [ ] **Step 1: Extend `Tunnel.Err`'s godoc**

It currently names the classes: "ErrCertificate, ErrRejected, ErrProviderUnreachable, ErrEdgeUnreachable, ErrRateLimited". Add the new one after `ErrRejected` so the list matches the package.

- [ ] **Step 2: Add the README row**

In the failure-class table, after the `ErrRejected` row:

```markdown
| `ErrCredentialRejected` | the edge refused these credentials — the tunnel is gone | never |
```

- [ ] **Step 3: Extend the README example**

The `switch` currently shows `ErrCertificate`, `ErrEdgeUnreachable` and `ErrFailed`. Add the case that motivates the class, since discarding a dead spec is the recovery a reader most needs shown:

```go
case errors.Is(conn.Err(), libtunnel.ErrCredentialRejected):
    // the spec you replayed names a tunnel that no longer exists —
    // discard it and mint fresh
```

- [ ] **Step 4: Verify the documented names exist**

Run: `go doc . 2>/dev/null | grep ErrCredentialRejected`

Expected: the façade re-export is listed.

- [ ] **Step 5: Commit**

```bash
gofmt -w . && go vet ./...
git add v1/v1.go README.md
git commit -m "docs: document ErrCredentialRejected

Refs #170"
```

---

## Finishing

- [ ] **Full offline suite:** `make test` — expected PASS.
- [ ] **Race lane:** `make race` — expected PASS. This is the one that matters
  for `edgeReject`, which crosses goroutines.
- [ ] **Live tier:** `make e2e`. It exercises the happy path, which must still
  connect — the bridge now runs at Warn instead of disabled, so watch for
  cloudflared warnings appearing in the output that were previously swallowed.
  That is expected, not a regression. A `served: error code: 1033` from a fresh
  tunnel is edge route propagation lag; rerun before investigating.
- [ ] **Open the PR** from `fix/edge-credential-rejection` with `Closes #170`
  in the body. Say in it that cloudflared warnings and errors now surface at
  the default log level, which is a visible behavior change, and that the
  live failure could not be reproduced deterministically — it needs a reaped
  tunnel's spec, so tunneld's next replay is the real confirmation.
