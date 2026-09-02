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
		v1.ErrCredentialRejected,
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
		{v1.ErrCredentialRejected, 0},
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

// TestCredentialRejectionIsItsOwnClass pins the distinction that motivates a
// separate class: a caller replaying a spec acts on this one by discarding it,
// which is the wrong move for a provider that declined to mint.
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
