# Tunnel Failure Classification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a tunnel that can never come up report why, instead of retrying forever behind a silent logger.

**Architecture:** `v1` gains a `class` error type carrying an umbrella (`ErrFailed`), a reason, and a retry budget; the exported sentinels are instances of it. `v1alpha1.Classify` is the single place an error becomes a class, and retryability stops being a separate fact — it is `v1.Budget(class) > 0`. The quick-tunnel retry loop consults both on every error at arrival, so every failure either short-circuits or expires its budget.

**Tech Stack:** Go 1.26, stdlib only (`errors`, `crypto/tls`, `crypto/x509`, `net`, `net/url`), `net/http/httptest` for tests.

**Spec:** `docs/superpowers/specs/2026-09-01-tunnel-error-classification-design.md`

## Global Constraints

- Go 1.26 or later (cloudflared's floor). Module `github.com/cnuss/libtunnel`.
- Import alias for the stable package is `v1 "github.com/cnuss/libtunnel/v1"` — match the existing files.
- Every exported identifier gets a godoc comment. Existing comments in this repo explain *why*, not *what*; match that register.
- No new dependencies.
- `v1` must not import `v1alpha1`. The dependency runs one way.
- Before each commit: `gofmt -w .` then `go vet ./...`.
- `make test` is the fast tier (`-short`); it must pass at the end of every task. `make e2e` mints real tunnels and is NOT part of the loop — run it once at the end.
- This is a deliberate breaking change to `v1`. Do not add compatibility shims or deprecated aliases.

---

### Task 1: The `v1` failure-class vocabulary

**Files:**
- Modify: `v1/v1.go:23-39` (replace the three `errors.New` sentinels)
- Modify: `v1/v1.go:13-21` (import block — add `"time"`)
- Test: `v1/errors_test.go` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `v1.ErrFailed error`; `v1.ErrCertificate`, `v1.ErrRejected`, `v1.ErrProviderUnreachable`, `v1.ErrEdgeUnreachable`, `v1.ErrRateLimited`, `v1.ErrClosed`, all declared with explicit type `error`; `func v1.Budget(err error) time.Duration`. The unexported `class` type is not part of the interface — nothing outside `v1/v1.go` may name it.

- [ ] **Step 1: Write the failing test**

Create `v1/errors_test.go`:

```go
package v1_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
)

// TestFailureClassesAnswerErrFailed pins the umbrella: every failure class is
// reachable by errors.Is through the wrapping a provider and TunnelImpl.Spec
// put around it, answers ErrFailed, keeps the underlying cause in the chain,
// and answers no other class.
func TestFailureClassesAnswerErrFailed(t *testing.T) {
	classes := []error{
		v1.ErrCertificate,
		v1.ErrRejected,
		v1.ErrProviderUnreachable,
		v1.ErrEdgeUnreachable,
		v1.ErrRateLimited,
	}
	cause := errors.New("underlying cause")
	for _, c := range classes {
		wrapped := fmt.Errorf("unable to fetch tunnel spec: %w", fmt.Errorf("%w: %w", c, cause))
		if !errors.Is(wrapped, c) {
			t.Errorf("errors.Is(_, %v) = false, want true", c)
		}
		if !errors.Is(wrapped, v1.ErrFailed) {
			t.Errorf("%v: errors.Is(_, ErrFailed) = false, want true", c)
		}
		if !errors.Is(wrapped, cause) {
			t.Errorf("%v: the underlying cause did not survive wrapping", c)
		}
		for _, other := range classes {
			if other == c {
				continue
			}
			if errors.Is(wrapped, other) {
				t.Errorf("errors.Is(%v, %v) = true, want false", c, other)
			}
		}
	}
}

// TestErrClosedIsNotAFailure pins that a deliberate shutdown stays outside the
// umbrella. It is terminal, but "it will not come up" is the wrong reading of
// a caller closing its own listener.
func TestErrClosedIsNotAFailure(t *testing.T) {
	if errors.Is(v1.ErrClosed, v1.ErrFailed) {
		t.Error("errors.Is(ErrClosed, ErrFailed) = true, want false")
	}
	if got, want := v1.ErrClosed.Error(), "tunnel closed"; got != want {
		t.Errorf("ErrClosed.Error() = %q, want %q", got, want)
	}
}

// TestFailureClassMessages pins the message shape: umbrella first, then the
// reason, so a log line reads "tunnel failed: certificate verification".
func TestFailureClassMessages(t *testing.T) {
	if got, want := v1.ErrCertificate.Error(), "tunnel failed: certificate verification"; got != want {
		t.Errorf("ErrCertificate.Error() = %q, want %q", got, want)
	}
}

// TestBudgets pins each class's budget. Zero is the whole retryability
// vocabulary: a class that never retries and a thing that is not a class at
// all both answer zero, so a caller never has to ask a second question.
func TestBudgets(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want time.Duration
	}{
		{v1.ErrCertificate, 0},
		{v1.ErrRejected, 0},
		{v1.ErrProviderUnreachable, 45 * time.Second},
		{v1.ErrEdgeUnreachable, 30 * time.Second},
		{v1.ErrRateLimited, 45 * time.Second},
		{v1.ErrClosed, 0},
		{errors.New("not a class"), 0},
		{nil, 0},
	} {
		if got := v1.Budget(tc.err); got != tc.want {
			t.Errorf("Budget(%v) = %s, want %s", tc.err, got, tc.want)
		}
	}
}

// TestBudgetThroughWrapping pins that the budget survives the wrapping the
// provider puts around a class — the retry loop reads it off the wrapped
// error, not off a bare sentinel.
func TestBudgetThroughWrapping(t *testing.T) {
	err := fmt.Errorf("unable to fetch tunnel spec: %w",
		fmt.Errorf("%w: resets in 12s", v1.ErrRateLimited))
	if got, want := v1.Budget(err), 45*time.Second; got != want {
		t.Errorf("Budget(wrapped) = %s, want %s", got, want)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./v1/ -run 'TestFailureClasses|TestErrClosed|TestFailureClassMessages|TestBudget' -v`

Expected: FAIL to build — `undefined: v1.ErrFailed`, `undefined: v1.ErrCertificate`, `undefined: v1.ErrProviderUnreachable`, `undefined: v1.ErrRateLimited`, `undefined: v1.Budget`.

- [ ] **Step 3: Add `"time"` to the `v1/v1.go` import block**

The block at `v1/v1.go:13-21` currently reads:

```go
import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
)
```

Add `"time"` as the last entry.

- [ ] **Step 4: Replace the sentinel block**

Delete `v1/v1.go:23-39` in full — the `ErrClosed`, `ErrEdgeUnreachable` and `ErrHostnameUnresolved` declarations and their comments — and put this in its place:

```go
// ErrFailed marks a tunnel that will not come up. Retrying will not help; the
// class wrapping it says what an operator can do about it. Every failure class
// below answers errors.Is(err, ErrFailed) — ErrClosed does not, because a
// deliberate shutdown is terminal without being a failure.
var ErrFailed = errors.New("tunnel failed")

// class is a terminal tunnel state: the umbrella it answers to (nil for a
// state that is not a failure), the reason it ended, and how long that class
// may keep failing before it becomes the verdict.
//
// The budget lives here rather than in a lookup beside the classifier so that
// "is this worth retrying" cannot disagree with "what kind of failure is
// this". It is one fact — Budget(class) > 0 — not two tables that have to be
// kept in step.
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

// Is puts the class under its umbrella. errors.Is reaches the class itself by
// identity; this answers for everything above it.
func (c *class) Is(target error) bool { return c.parent != nil && errors.Is(c.parent, target) }

var (
	// ErrCertificate is the Err result of a tunnel whose provider's
	// certificate could not be verified — a missing trust store (a scratch
	// container with no CA bundle), a wrong system clock, or an intercepting
	// proxy. None of those change on a retry, so the budget is zero.
	ErrCertificate error = &class{ErrFailed, "certificate verification", 0}

	// ErrRejected is the Err result of a mint the provider definitively
	// refused, or of a request libtunnel could not construct at all: an API
	// URL with a scheme no transport handles, a header that cannot go on the
	// wire, a hostname no resolver will ever answer. All configuration, none
	// of it retryable.
	ErrRejected error = &class{ErrFailed, "rejected by the provider", 0}

	// ErrProviderUnreachable is the Err result of a mint endpoint that never
	// answered: it refuses, times out, or keeps returning 5xx for the budget.
	//
	// Forty-five seconds is three full mint attempts. The mint request
	// carries a 15s Timeout, sized so the header wait covers a server-side
	// mint that waits out DNS propagation, so a hung endpoint burns 15s an
	// attempt — and any bound under 30s could not tell a dead endpoint from
	// one bad attempt. For failures that return immediately the provider's
	// linear ramp governs instead, and 45s buys about nine attempts, which
	// outlasts a container resolver that comes up late.
	ErrProviderUnreachable error = &class{ErrFailed, "provider unreachable", 45 * time.Second}

	// ErrEdgeUnreachable is the Err result of a tunnel that never reached its
	// backend's edge. The engine retries the edge indefinitely, so without a
	// bound a blocked network is indistinguishable from a slow one and the
	// tunnel hangs until the caller's context expires; the bound turns it into
	// an error a caller can act on and a message that names the likely cause.
	//
	// Thirty seconds is a bound on one transport, not a race against a
	// fallback to another: the Cloudflare engine pins the edge to TCP, so
	// there is no quic->http2 recovery in flight that a short bound could cut
	// off. An earlier version of this had to outlast that fallback and did
	// not, failing a CI runner after four QUIC attempts while http2 was still
	// ahead of it. With the transport fixed, a TCP connect and registration
	// that has not happened in thirty seconds is not going to.
	//
	// The bound covers the first connection only. A connection dropped later
	// is the engine's to retry indefinitely, which is the right policy for a
	// tunnel that has already proven the network works.
	ErrEdgeUnreachable error = &class{ErrFailed, "edge unreachable", 30 * time.Second}

	// ErrRateLimited is the Err result of a mint the provider throttled for
	// longer than the budget, or throttled with an advertised reset longer
	// than the budget — which is reported immediately rather than waited out,
	// so a caller can act on "resets in 5m" instead of blocking on it.
	//
	// The budget matches ErrProviderUnreachable for want of better evidence:
	// it only governs a 429 that carries no reset at all, since one that names
	// its reset is decided by that number instead.
	ErrRateLimited error = &class{ErrFailed, "rate limited", 45 * time.Second}

	// ErrClosed is the Err result of a tunnel shut down deliberately — by
	// closing the listener returned from Tunnel.Listener. It is terminal but
	// it is not a failure, so it has no umbrella: the message is a bare
	// "tunnel closed" and errors.Is(err, ErrFailed) is false.
	ErrClosed error = &class{nil, "tunnel closed", 0}
)

// Budget reports how long the failure class err belongs to may keep failing
// before it becomes the verdict — and so also whether it is worth retrying at
// all. Zero never retries, which covers both a permanent class and anything
// that is not a failure class in the first place.
func Budget(err error) time.Duration {
	var c *class
	if errors.As(err, &c) {
		return c.budget
	}
	return 0
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./v1/ -run 'TestFailureClasses|TestErrClosed|TestFailureClassMessages|TestBudget' -v`

Expected: PASS, all five tests.

- [ ] **Step 6: Confirm the rest of the module still builds**

Run: `go build ./...`

Expected: success. `v1alpha1/tunnel.go:460` passes `v1.ErrClosed` to `cancel`, which takes an `error` — the type change from an `errors.New` value to an `error`-typed `*class` is invisible there. If the build fails anywhere on `ErrHostnameUnresolved`, that reference was missed by the spec's survey — delete it, the variable produced no error even before this change.

- [ ] **Step 7: Commit**

```bash
gofmt -w . && go vet ./...
git add v1/v1.go v1/errors_test.go
git commit -m "feat: carry the retry budget on the tunnel failure class

Replaces v1's three errors.New sentinels with a class type holding its
umbrella, reason and budget. errors.Is(err, ErrFailed) is the coarse 'it will
not come up' check and the class is the reason; Budget(err) > 0 is the whole
retryability vocabulary, so it cannot disagree with the class.

ErrClosed joins the same machinery with no umbrella: terminal, but a clean
shutdown is not a failure. ErrHostnameUnresolved is deleted, having produced
no error since readiness stopped polling DNS.

Refs #162"
```

---

### Task 2: `Classify` — one place an error becomes a class

**Files:**
- Create: `v1alpha1/errors.go`
- Test: `v1alpha1/errors_test.go` (create)

**Interfaces:**
- Consumes: `v1.ErrCertificate`, `v1.ErrRejected`, `v1.ErrProviderUnreachable`, `v1.ErrEdgeUnreachable`, `v1.ErrRateLimited`, `v1.ErrClosed`, `v1.Budget` from Task 1.
- Produces: `func v1alpha1.Classify(err error) error` — returns one of the `v1` classes, or `nil` for a `nil` input. There is no second return value; callers ask `v1.Budget(class) > 0`.

- [ ] **Step 1: Write the failing test**

Create `v1alpha1/errors_test.go`:

```go
package v1alpha1_test

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// TestClassifyUntrustedCertificate drives a real TLS handshake against a
// server no trust store knows — the failure #162 was reported for, from a
// container shipping no CA bundle.
func TestClassifyUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	// http.DefaultClient deliberately, not srv.Client(): the missing trust is
	// the point of the test.
	resp, err := http.Post(srv.URL, "application/json", nil)
	if err == nil {
		resp.Body.Close()
		t.Fatal("request succeeded against an untrusted certificate")
	}
	if got := v1alpha1.Classify(err); got != v1.ErrCertificate {
		t.Errorf("Classify(%v) = %v, want ErrCertificate", err, got)
	}
	if v1.Budget(v1alpha1.Classify(err)) != 0 {
		t.Error("a certificate failure has a non-zero budget; it would be retried")
	}
}

// TestClassifyNXDOMAIN uses the reserved .invalid TLD (RFC 2606), which no
// resolver will ever answer. A name that does not exist is configuration, so
// it lands in ErrRejected rather than being retried.
func TestClassifyNXDOMAIN(t *testing.T) {
	resp, err := http.Get("http://libtunnel-does-not-exist.invalid/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("request to a .invalid host succeeded")
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Skipf("resolver did not return NXDOMAIN (captive portal or wildcard DNS): %v", err)
	}
	if got := v1alpha1.Classify(err); got != v1.ErrRejected {
		t.Errorf("Classify(%v) = %v, want ErrRejected", err, got)
	}
}

// TestClassifyConnectionRefused pins the retryable shape: a provider that is
// down now may be up in a second, so it gets a budget rather than a verdict.
func TestClassifyConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // free the port so the dial is refused rather than accepted

	resp, err := http.Get("http://" + addr + "/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("request to a closed port succeeded")
	}
	if got := v1alpha1.Classify(err); got != v1.ErrProviderUnreachable {
		t.Errorf("Classify(%v) = %v, want ErrProviderUnreachable", err, got)
	}
}

// TestClassifyUnsupportedScheme pins the request libtunnel could not even
// build: a WithApiURL typo is configuration, not weather.
func TestClassifyUnsupportedScheme(t *testing.T) {
	resp, err := http.Post("gopher://example.invalid/tunnel", "application/json", nil)
	if err == nil {
		resp.Body.Close()
		t.Fatal("request with an unsupported scheme succeeded")
	}
	if got := v1alpha1.Classify(err); got != v1.ErrRejected {
		t.Errorf("Classify(%v) = %v, want ErrRejected", err, got)
	}
}

// TestClassifyIsIdempotent pins rule one: an error a provider already named
// comes back as it arrived, however deeply it is wrapped. This is what lets a
// backend tag the verdicts only its protocol can read and leave the rest here.
func TestClassifyIsIdempotent(t *testing.T) {
	for _, want := range []error{
		v1.ErrCertificate,
		v1.ErrRejected,
		v1.ErrProviderUnreachable,
		v1.ErrEdgeUnreachable,
		v1.ErrRateLimited,
		v1.ErrClosed,
	} {
		err := fmt.Errorf("unable to fetch tunnel spec: %w",
			fmt.Errorf("%w: %w", want, errors.New("cause")))
		if got := v1alpha1.Classify(err); got != want {
			t.Errorf("Classify(%v) = %v, want %v", err, got, want)
		}
	}
}

// TestClassifyNil pins that a nil error stays nil rather than becoming a
// failure — Classify is called on the error path, but defensively.
func TestClassifyNil(t *testing.T) {
	if got := v1alpha1.Classify(nil); got != nil {
		t.Errorf("Classify(nil) = %v, want nil", got)
	}
}

// TestClassifyUnknownIsRetryable pins the default. An error nothing recognizes
// must land in a class with a budget: that is what stops an unanticipated
// failure from looping forever, which is the whole complaint in #162.
func TestClassifyUnknownIsRetryable(t *testing.T) {
	got := v1alpha1.Classify(errors.New("something nobody anticipated"))
	if got != v1.ErrProviderUnreachable {
		t.Errorf("Classify(unknown) = %v, want ErrProviderUnreachable", got)
	}
	if v1.Budget(got) == 0 {
		t.Error("the default class has a zero budget; an unknown error would never be retried")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./v1alpha1/ -run TestClassify -v`

Expected: FAIL to build — `undefined: v1alpha1.Classify`.

- [ ] **Step 3: Write the implementation**

Create `v1alpha1/errors.go`:

```go
package v1alpha1

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"strings"

	v1 "github.com/cnuss/libtunnel/v1"
)

// Classify names err with the v1 failure class that describes it.
//
// An error that already carries a class is returned as it arrived. A provider
// naming a verdict only its own protocol can read — a mint refused, a 429 —
// has already done the classification, and re-reading it here would only lose
// information. Everything else is read at the transport level, which every
// backend shares, so a backend never needs a classifier of its own: it tags
// what only it can see and lets this decide the rest.
//
// Whether the result is worth retrying is deliberately not a second return
// value. It is v1.Budget(class) > 0, which cannot drift out of step with the
// class the way a parallel table could.
func Classify(err error) error {
	if err == nil {
		return nil
	}

	for _, known := range []error{
		v1.ErrCertificate,
		v1.ErrRejected,
		v1.ErrProviderUnreachable,
		v1.ErrEdgeUnreachable,
		v1.ErrRateLimited,
		v1.ErrClosed,
	} {
		if errors.Is(err, known) {
			return known
		}
	}

	// A certificate the client cannot verify means a missing trust store, a
	// wrong clock, or an intercepting proxy — permanent conditions a retry
	// cannot see, let alone fix. This is where hashicorp/go-retryablehttp
	// draws the same line.
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var badHostname x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	if errors.As(err, &verification) ||
		errors.As(err, &unknownAuthority) ||
		errors.As(err, &badHostname) ||
		errors.As(err, &invalidCert) {
		return v1.ErrCertificate
	}

	// NXDOMAIN is the resolver saying the host does not exist, and it will
	// keep saying so — a typo'd provider, not a slow one. A resolver that is
	// merely not up yet reports something else (SERVFAIL, a timeout) and
	// falls through to the retryable class at the bottom.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return v1.ErrRejected
	}

	// A request the client could not even build. net/http reports both of
	// these as plain text inside a *url.Error with no type to match on, so
	// matching the text is the only handle there is — the same compromise
	// go-retryablehttp makes with its regexps.
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		msg := urlErr.Err.Error()
		if strings.Contains(msg, "unsupported protocol scheme") ||
			strings.Contains(msg, "invalid header field") {
			return v1.ErrRejected
		}
	}

	// Everything unrecognized is retryable but bounded. An unanticipated
	// failure must still terminate: a class with a budget is what keeps a
	// caller that passed context.Background() from hanging forever.
	return v1.ErrProviderUnreachable
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./v1alpha1/ -run TestClassify -v`

Expected: PASS. `TestClassifyNXDOMAIN` may report SKIP on a network with wildcard DNS or a captive portal — that is the intended behavior, not a failure.

- [ ] **Step 5: Commit**

```bash
gofmt -w . && go vet ./...
git add v1alpha1/errors.go v1alpha1/errors_test.go
git commit -m "feat: classify transport failures into v1 failure classes

Classify is the one place an error becomes a class. It returns an already
named error untouched, so a backend tags only the verdicts its own protocol
can read and never needs a classifier of its own; everything else is read at
the transport level every backend shares.

No retryable bool: that is Budget(class) > 0, which cannot drift out of step
with the class. Anything unrecognized lands in a class with a budget, so an
unanticipated failure still terminates.

Refs #162"
```

---

### Task 3: Quick-tunnel names its own verdicts in the shared vocabulary

**Files:**
- Modify: `v1alpha1/cloudflare/quicktunnel.go:23-32` (delete both sentinels)
- Modify: `v1alpha1/cloudflare/quicktunnel.go:185,190,194,196` (429 → `v1.ErrRateLimited`)
- Modify: `v1alpha1/cloudflare/quicktunnel.go:221` (rejection → `v1.ErrRejected`)
- Modify: `v1alpha1/cloudflare/quicktunnel.go:235` (reclaim check → `v1.ErrRejected`)
- Modify: `v1alpha1/cloudflare/quicktunnel.go:252` (rate-limit log branch → `v1.ErrRateLimited`)
- Test: `v1alpha1/cloudflare/cloudflare_test.go:469,1137,1174` (update existing assertions)

**Interfaces:**
- Consumes: `v1.ErrRejected`, `v1.ErrRateLimited` from Task 1.
- Produces: `cloudflare.ErrMintRejected` and `cloudflare.ErrRateLimited` no longer exist. `QuickTunnelProvider.Spec` returns errors wrapping the `v1` classes. The retry loop's shape is unchanged in this task — only the vocabulary moves.

- [ ] **Step 1: Update the existing tests to the new vocabulary**

These are the failing tests for this task — the assertions come first, the code follows.

In `v1alpha1/cloudflare/cloudflare_test.go`, `TestExplicitHintRejectionStaysTerminal` (around `:469`):

```go
	if !errors.Is(err, v1.ErrRejected) {
		t.Errorf("err = %v, want errors.Is(_, v1.ErrRejected)", err)
	}
```

`TestQuickTunnelRejectionIsPermanent` (around `:1137`), the same substitution:

```go
	if !errors.Is(err, v1.ErrRejected) {
		t.Errorf("err = %v, want errors.Is(_, v1.ErrRejected)", err)
	}
```

`TestQuickTunnelSurfacesRateLimit` (around `:1174`):

```go
	if !errors.Is(err, v1.ErrRateLimited) {
		t.Errorf("err = %v, want errors.Is(_, v1.ErrRateLimited)", err)
	}
```

Leave everything else in those three tests alone — including the 1500ms context and the log assertion in `TestQuickTunnelSurfacesRateLimit`. Task 4 revisits that one.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./v1alpha1/cloudflare/ -run 'TestExplicitHintRejectionStaysTerminal|TestQuickTunnelRejectionIsPermanent|TestQuickTunnelSurfacesRateLimit' -v`

Expected: FAIL — the assertions now name classes the provider does not yet return, so `errors.Is` is false and each test reports `err = ... want errors.Is(...)`.

- [ ] **Step 3: Delete the provider-local sentinels**

Delete `v1alpha1/cloudflare/quicktunnel.go:23-32` in full — both the `ErrRateLimited` and `ErrMintRejected` declarations and their comments. Nothing replaces them in this file; the vocabulary now lives in `v1`.

- [ ] **Step 4: Point the four rate-limit sites at `v1.ErrRateLimited`**

In the 429 block (`quicktunnel.go:176-196`), replace each bare `ErrRateLimited` with `v1.ErrRateLimited`. There are four, and the surrounding format strings do not change:

```go
			if secs, err := strconv.Atoi(retryAfter); err == nil && secs > 0 {
				d := time.Duration(secs) * time.Second
				return nil, d, fmt.Errorf("%w: resets in %s", v1.ErrRateLimited, d)
			}
			// RFC 7231 also allows an HTTP-date form.
			if when, err := http.ParseTime(retryAfter); err == nil {
				if d := time.Until(when); d > 0 {
					return nil, d, fmt.Errorf("%w: resets in %s", v1.ErrRateLimited, d.Round(time.Second))
				}
			}
			if retryAfter != "" {
				return nil, 0, fmt.Errorf("%w (HTTP 429): Retry-After=%s", v1.ErrRateLimited, retryAfter)
			}
			return nil, 0, fmt.Errorf("%w (HTTP 429): no rate-limit headers returned", v1.ErrRateLimited)
```

- [ ] **Step 5: Point the rejection sites at `v1.ErrRejected`**

At `quicktunnel.go:221`, inside the `!data.Success` branch:

```go
			// A parsed success=false on a non-5xx response is the API saying
			// no, not the API having a bad moment — retrying can't fix it.
			if resp.StatusCode < http.StatusInternalServerError {
				return nil, 0, fmt.Errorf("%w: %s", v1.ErrRejected, strings.Join(errorMessages, "; "))
			}
```

At `quicktunnel.go:235`, the reclaim check:

```go
		if errors.Is(err, v1.ErrRejected) {
```

At `quicktunnel.go:252`, the log branch:

```go
		if errors.Is(err, v1.ErrRateLimited) {
```

- [ ] **Step 6: Run the full cloudflare suite**

Run: `go test ./v1alpha1/cloudflare/ -short`

Expected: PASS. The three tests from Step 1 now pass, and every other quick-tunnel test is unaffected — the loop still retries forever, so `TestQuickTunnelHonorsContext`, `TestQuickTunnelRetriesAfter429` and the two `Retry-After` tests behave exactly as before.

- [ ] **Step 7: Commit**

```bash
gofmt -w . && go vet ./...
git add v1alpha1/cloudflare/quicktunnel.go v1alpha1/cloudflare/cloudflare_test.go
git commit -m "refactor: retire the provider-local error sentinels

ErrMintRejected and ErrRateLimited become v1.ErrRejected and
v1.ErrRateLimited. fetch keeps naming the two verdicts only the quick-tunnel
protocol can read — it just names them in the vocabulary every backend and
every caller shares, so Classify recognizes them instead of re-reading them.

Behavior is unchanged: the retry loop still runs to the caller's context.
Task 4 bounds it.

Refs #162"
```

---

### Task 4: The retry loop consults the classifier and the budgets

**Files:**
- Modify: `v1alpha1/cloudflare/quicktunnel.go:228-265` (the retry loop)
- Modify: `v1alpha1/cloudflare/quicktunnel.go` (add the `budget` package var near the top, below the imports)
- Test: `v1alpha1/cloudflare/cloudflare_test.go` (add three tests; adjust `TestQuickTunnelSurfacesRateLimit`)

**Interfaces:**
- Consumes: `v1alpha1.Classify` (Task 2), `v1.Budget` (Task 1).
- Produces: `var budget = v1.Budget` — an unexported package var in `cloudflare`, the seam tests override to drive expiry in milliseconds. `QuickTunnelProvider.Spec` now returns rather than looping when a class has no budget or has spent it.

- [ ] **Step 1: Write the failing tests**

Append to `v1alpha1/cloudflare/cloudflare_test.go`. The package is `cloudflare` (internal), so these reach the `budget` seam directly.

```go
// shortBudgets swaps the retry budgets for millisecond ones so a test can
// drive a loop to expiry without sleeping through the real 45 seconds. The
// seam is the package var, following the URL seam these tests already use.
func shortBudgets(t *testing.T, d time.Duration) {
	t.Helper()
	prev := budget
	budget = func(err error) time.Duration {
		if prev(err) == 0 {
			return 0
		}
		return d
	}
	t.Cleanup(func() { budget = prev })
}

// TestQuickTunnelUnreachableExpiresBudget pins the fix for #162 on the
// retryable side: a provider that never recovers stops looking like a slow
// one, and says so through a class with the cause still in the chain.
func TestQuickTunnelUnreachableExpiresBudget(t *testing.T) {
	shortBudgets(t, 100*time.Millisecond)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":1,"message":"boom"}]}`)
	}))
	defer srv.Close()

	// context.Background(): the budget is the only way out, which is the
	// case the issue reported as unfixable from outside the library.
	_, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if !errors.Is(err, v1.ErrProviderUnreachable) {
		t.Fatalf("err = %v, want errors.Is(_, v1.ErrProviderUnreachable)", err)
	}
	if !errors.Is(err, v1.ErrFailed) {
		t.Errorf("err = %v, want errors.Is(_, v1.ErrFailed)", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v, want the last cause still in the message", err)
	}
	if got := calls.Load(); got < 2 {
		t.Errorf("API called %d times, want at least 2 (the budget must allow a retry)", got)
	}
}

// TestQuickTunnelCertificateFailsImmediately pins the non-retryable side: the
// x509 failure from the issue report returns on the first attempt rather than
// burning a budget on a condition no retry can change.
func TestQuickTunnelCertificateFailsImmediately(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, specJSON)
	}))
	defer srv.Close()

	// The provider builds its own client, which has no reason to trust
	// httptest's throwaway CA — exactly a container with no CA bundle.
	_, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if !errors.Is(err, v1.ErrCertificate) {
		t.Fatalf("err = %v, want errors.Is(_, v1.ErrCertificate)", err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("handler reached %d times, want 0 (the handshake must fail first)", got)
	}
}

// TestQuickTunnelLongResetFailsImmediately pins that a throttle outlasting its
// own budget is reported rather than slept on: the caller can act on the reset
// now, where waiting it out would just relocate the hang.
func TestQuickTunnelLongResetFailsImmediately(t *testing.T) {
	shortBudgets(t, 100*time.Millisecond)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if !errors.Is(err, v1.ErrRateLimited) {
		t.Fatalf("err = %v, want errors.Is(_, v1.ErrRateLimited)", err)
	}
	if !strings.Contains(err.Error(), "resets in") {
		t.Errorf("err = %v, want the advertised reset in the message", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("returned after %s, want immediately (the 120s reset must not be waited out)", elapsed)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("API called %d times, want 1", got)
	}
}
```

Then adjust `TestQuickTunnelSurfacesRateLimit` (around `:1160`). Its handler already advertises `Retry-After: 120`, which now short-circuits, so the 1500ms context is no longer what ends it. Replace the context with `context.Background()` and keep both existing assertions:

```go
	_, err := (&QuickTunnelProvider{URL: srv.URL, Log: log}).Spec(context.Background())
	if !errors.Is(err, v1.ErrRateLimited) {
		t.Errorf("err = %v, want errors.Is(_, v1.ErrRateLimited)", err)
	}
	if !strings.Contains(buf.String(), "quick tunnel rate limited") {
		t.Errorf("no rate-limit warning logged; log output:\n%s", buf.String())
	}
```

Delete the now-unused `ctx, cancel := context.WithTimeout(...)` and its `defer cancel()` from that test.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./v1alpha1/cloudflare/ -run 'TestQuickTunnelUnreachableExpiresBudget|TestQuickTunnelCertificateFailsImmediately|TestQuickTunnelLongResetFailsImmediately|TestQuickTunnelSurfacesRateLimit' -v -timeout 30s`

Expected: FAIL to build — `undefined: budget`.

The `-timeout 30s` matters here and nowhere else in this plan. Once Step 3 adds the seam, these tests compile but the loop is still unbounded, so `TestQuickTunnelUnreachableExpiresBudget` and `TestQuickTunnelLongResetFailsImmediately` retry forever against `context.Background()`. Without the flag the red state is a ten-minute wait; with it, a panic naming the hung test in half a minute. That hang is the bug being fixed — seeing it is the point of the step.

- [ ] **Step 3: Add the budget seam**

In `v1alpha1/cloudflare/quicktunnel.go`, below the `quickTunnelURL` const (where the deleted sentinels used to be):

```go
// budget is v1.Budget behind a package var so a test can shorten the retry
// budgets instead of sleeping through them. Production never reassigns it —
// this is the same seam shape QuickTunnelProvider.URL already is for the
// endpoint.
var budget = v1.Budget
```

- [ ] **Step 4: Rewrite the retry loop**

Replace `v1alpha1/cloudflare/quicktunnel.go:228-265` — everything from `sleep := 0 * time.Second` to the closing brace of the `for` loop — with:

```go
	sleep := 0 * time.Second
	hints := cacheHints
	attempts := 0
	// Each class keeps its own clock, started at its first failure, so a mint
	// that hits a rate limit and then a flaky resolver is not charged twice
	// for one slow start. The clock is wall time rather than a sum of the
	// backoff waits: three 15s timeouts cost 45s of real time but only 6s of
	// ramp, and a hang is exactly what the budget exists to catch.
	since := map[error]time.Time{}
	for {
		attempts++
		spec, retryAfter, err := fetch(hints)
		if err == nil {
			return spec, nil
		}

		if errors.Is(err, v1.ErrRejected) && len(hints) > 0 {
			// The backend declined to hand the cached tunnel back (reaped
			// and unreclaimable, claimed elsewhere). That verdict is about
			// the reclaim, not about a fresh mint — retry once, immediately,
			// without the cache-derived hints. A rejection of the retry has
			// no hints left and falls through below, terminal, exactly as
			// when no cache was involved.
			log.Warn("cached spec refused by the mint provider, minting fresh", "error", err)
			hints = nil
			continue
		}

		class := v1alpha1.Classify(err)
		// named is err with its class attached — unless fetch already named
		// it, in which case attaching it again would only say the same thing
		// twice in the message.
		named := err
		if !errors.Is(err, class) {
			named = fmt.Errorf("%w: %w", class, err)
		}

		limit := budget(class)
		if limit == 0 {
			return nil, named
		}
		// A throttle that outlasts its own budget is reported now rather than
		// slept on: a caller can act on "resets in 5m", where waiting it out
		// just moves the hang somewhere the caller cannot see it.
		if retryAfter > limit {
			log.Warn("quick tunnel rate limited", "error", err, "resetsIn", retryAfter)
			return nil, named
		}
		if _, seen := since[class]; !seen {
			since[class] = time.Now()
		}
		// Checked before the wait, so the worst case is the budget plus one
		// attempt — a hung endpoint is reported at roughly budget + Timeout,
		// not at the budget exactly.
		if spent := time.Since(since[class]); spent > limit {
			return nil, fmt.Errorf("no spec after %d attempts in %s: %w",
				attempts, spent.Round(time.Second), named)
		}

		// The server's Retry-After wins over the linear ramp when it asks for
		// longer; either way the wait is bounded by ctx and by the budget.
		sleep += 1 * time.Second
		wait := max(sleep, retryAfter)
		if errors.Is(err, v1.ErrRateLimited) {
			log.Warn("quick tunnel rate limited, retrying...", "error", err, "nextAttemptIn", wait)
		} else {
			log.Warn("failed to fetch tunnel spec, retrying...", "error", err)
		}

		select {
		case <-ctx.Done():
			// Keep the last fetch failure in the chain so callers can see
			// (and errors.Is) why minting never succeeded.
			return nil, errors.Join(ctx.Err(), err)
		case <-time.After(wait):
		}
	}
```

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `go test ./v1alpha1/cloudflare/ -run 'TestQuickTunnelUnreachableExpiresBudget|TestQuickTunnelCertificateFailsImmediately|TestQuickTunnelLongResetFailsImmediately|TestQuickTunnelSurfacesRateLimit' -v`

Expected: PASS, all four.

- [ ] **Step 6: Run the whole cloudflare suite for regressions**

Run: `go test ./v1alpha1/cloudflare/ -short -count=1`

Expected: PASS. Watch three in particular. `TestQuickTunnelRetriesAfter429` advertises `Retry-After: 1`, under the real 45s budget, so it still retries and succeeds. `TestQuickTunnelHonorsRetryAfterSeconds` and `TestQuickTunnelHonorsRetryAfterDate` ask for 2s and ~3s, also under budget, so both still wait and succeed. `TestQuickTunnelHonorsContext` uses a 100ms context against a persistent 500, which expires long before the 45s budget, so it still returns via `ctx.Err()`.

Also confirm the reclaim path specifically: the cache-hint rejection test around `:441` asserts that a refused cached spec is followed by a fresh mint whose hostname comes back. That is §5 of the spec — the one behavior this rewrite could silently break, since the `errors.Is(err, v1.ErrRejected) && len(hints) > 0` branch now falls through to a terminal return instead of the old early one.

- [ ] **Step 7: Commit**

```bash
gofmt -w . && go vet ./...
git add v1alpha1/cloudflare/quicktunnel.go v1alpha1/cloudflare/cloudflare_test.go
git commit -m "fix: bound the mint retry loop with per-class budgets

The loop asks Classify what a failure is the moment it arrives. A class with
no budget returns at once — the x509 failure from the report no longer loops
on a condition no retry can change — and a class with one gets wall-clock
time, measured from its first failure, before its class becomes the verdict.

A caller that passed context.Background() now has a way out by construction,
which was the part of #162 no caller could work around.

Refs #162"
```

---

### Task 5: The edge path reads its budget from its class

**Files:**
- Modify: `v1alpha1/cloudflare/cloudflare.go:845-855` (the connect timer and its error)
- Modify: `v1alpha1/cloudflare/cloudflare.go:859-876` (delete the `edgeTimeout` const and its comment)
- Test: `v1alpha1/cloudflare/cloudflare_test.go:1238` (update the expected message)

**Interfaces:**
- Consumes: `v1.ErrEdgeUnreachable`, `v1.Budget` from Task 1.
- Produces: `cloudflare.edgeTimeout` no longer exists. `edgeBlockedHint` is unchanged and stays in this file.

**No red step here, on purpose.** This task moves a constant without changing
a behavior: `edgeTimeout` and `v1.Budget(v1.ErrEdgeUnreachable)` are both 30s,
so no test can distinguish before from after. Manufacturing a failing test for
a pure refactor would be theater. The safety net is that the existing edge
tests keep passing and the deleted symbol has no remaining references.

- [ ] **Step 1: Update the existing test**

In `v1alpha1/cloudflare/cloudflare_test.go`, `TestEdgeUpWatcherCountsAttempts` builds the expected message at `:1238`. Replace `edgeTimeout` with the budget lookup:

```go
		v1.ErrEdgeUnreachable, 3, v1.Budget(v1.ErrEdgeUnreachable), edgeBlockedHint)
```

- [ ] **Step 2: Confirm it still passes against the unchanged code**

Run: `go test ./v1alpha1/cloudflare/ -run TestEdgeUpWatcherCountsAttempts -v`

Expected: PASS — both sides render 30s. This confirms the test now reads the budget without yet depending on the code change, so a failure in Step 5 would be the code's fault and nothing else.

- [ ] **Step 3: Read the budget in `connect`**

At `v1alpha1/cloudflare/cloudflare.go:845-855`, replace:

```go
	timeout := time.NewTimer(edgeTimeout)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connected.Wait():
	case <-timeout.C:
		return fmt.Errorf("%w: no connection after %d attempts in %s: %s",
			v1.ErrEdgeUnreachable, b.edgeUp.attemptCount(), edgeTimeout, edgeBlockedHint)
	}
	return nil
```

with:

```go
	// The bound on the first edge connection, read off the class that reports
	// it — see v1.ErrEdgeUnreachable for why thirty seconds and why only the
	// first connection.
	edgeBudget := v1.Budget(v1.ErrEdgeUnreachable)
	timeout := time.NewTimer(edgeBudget)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connected.Wait():
	case <-timeout.C:
		return fmt.Errorf("%w: no connection after %d attempts in %s: %s",
			v1.ErrEdgeUnreachable, b.edgeUp.attemptCount(), edgeBudget, edgeBlockedHint)
	}
	return nil
```

- [ ] **Step 4: Delete the const**

Delete `v1alpha1/cloudflare/cloudflare.go:859-876` — the whole `edgeTimeout` comment block and the `const edgeTimeout = 30 * time.Second` line. Its reasoning already moved to `v1.ErrEdgeUnreachable`'s godoc in Task 1; do not leave a copy behind. Leave `edgeBlockedHint` and its comment exactly where they are.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./v1alpha1/cloudflare/ -short -count=1`

Expected: PASS. Also confirm nothing still references the deleted const:

Run: `grep -rn edgeTimeout .`

Expected: no matches.

- [ ] **Step 6: Commit**

```bash
gofmt -w . && go vet ./...
git add v1alpha1/cloudflare/cloudflare.go v1alpha1/cloudflare/cloudflare_test.go
git commit -m "refactor: read the edge bound off the class that reports it

edgeTimeout's 30s moves onto v1.ErrEdgeUnreachable, so both bounds in the
library now live with the class they produce and one lookup answers for the
mint path and the edge path alike. The number and its reasoning are unchanged;
only their home is.

Refs #162"
```

---

### Task 6: Document the failure classes

**Files:**
- Modify: `v1/v1.go` (the `Err() error` godoc in the `Tunnel` interface, around `:291`)
- Modify: `README.md:118` (the `Err()` line in the interface sketch)
- Modify: `README.md` (add a short subsection after the interface sketch block)

**Interfaces:**
- Consumes: the vocabulary from Task 1. Produces no code.

- [ ] **Step 1: Point `Tunnel.Err`'s godoc at the classes**

In `v1/v1.go`, the interface method currently reads:

```go
	// Err reports why the tunnel ended (nil while it is alive).
	Err() error
```

Replace the comment with:

```go
	// Err reports why the tunnel ended (nil while it is alive). A tunnel that
	// will not come up reports a failure class: errors.Is(err, ErrFailed) is
	// the coarse check, and the class wrapping it — ErrCertificate,
	// ErrRejected, ErrProviderUnreachable, ErrEdgeUnreachable, ErrRateLimited
	// — is what an operator can act on. A tunnel closed deliberately reports
	// ErrClosed, which is terminal but not a failure.
	Err() error
```

- [ ] **Step 2: Update the README interface sketch**

`README.md:118` currently reads:

```
    Err() error                     // why (nil while alive)
```

Replace with:

```
    Err() error                     // why (nil while alive); see Failure classes
```

- [ ] **Step 3: Add the README subsection**

Immediately after the closing fence of the interface sketch block that ends with the `With…` mutators, add:

````markdown
### Failure classes

A tunnel that will not come up ends with a class off `Err()`, so a caller
branches on the failure rather than on the text of a message it did not write:

```go
switch {
case errors.Is(tun.Err(), libtunnel.ErrCertificate):
    // no CA bundle, a wrong clock, or an intercepting proxy
case errors.Is(tun.Err(), libtunnel.ErrEdgeUnreachable):
    // egress to port 7844 is blocked — WithEdge routes around it
case errors.Is(tun.Err(), libtunnel.ErrFailed):
    // it will not come up, and the message says why
}
```

| class | meaning | retried for |
|---|---|---|
| `ErrCertificate` | the provider's certificate could not be verified | never |
| `ErrRejected` | the provider said no, or the request could not be built | never |
| `ErrProviderUnreachable` | the mint endpoint refuses, times out or 5xxs | 45s |
| `ErrEdgeUnreachable` | the edge never accepted a connection | 30s |
| `ErrRateLimited` | throttled past its budget, or past its advertised reset | 45s |
| `ErrClosed` | shut down deliberately — terminal, but not a failure | n/a |

`libtunnel.Budget(err)` reports how long a class is retried for; zero means it
never is. Every class except `ErrClosed` answers
`errors.Is(err, libtunnel.ErrFailed)`.
````

- [ ] **Step 4: Verify the documented names exist**

Run: `go doc ./v1 | grep -E 'Err(Failed|Certificate|Rejected|ProviderUnreachable|EdgeUnreachable|RateLimited|Closed)|func Budget'`

Expected: every name in the README table appears, and `func Budget(err error) time.Duration` is listed.

- [ ] **Step 5: Commit**

```bash
gofmt -w . && go vet ./...
git add v1/v1.go README.md
git commit -m "docs: document the tunnel failure classes

Refs #162"
```

---

## Finishing

- [ ] **Full offline suite:** `make test` — expected PASS.
- [ ] **Race lane:** `make race` — expected PASS.
- [ ] **Live tier once:** `make e2e`. A `served: error code: 1033` from a fresh
  tunnel is edge route propagation lag, not this change — rerun before
  investigating.
- [ ] **Open the PR** from `fix/error-classification` with `Closes #162` in the
  body, and say in it that this is a deliberate breaking change to `v1`:
  `ErrHostnameUnresolved`, `cloudflare.ErrMintRejected` and
  `cloudflare.ErrRateLimited` are gone, and `ErrClosed` / `ErrEdgeUnreachable`
  keep their names but change type.
