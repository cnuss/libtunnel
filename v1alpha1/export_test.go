package v1alpha1

import (
	"context"
	"log/slog"

	"github.com/cnuss/libtunnel/v1alpha1/resolver"
)

// SetAuthoritativeProbe overrides the hostname-readiness consensus probe for
// tests and returns a function that restores the production probe. It lets
// readiness fire deterministically without live DNS; the real probe is
// exercised by the live e2e suite. The swap is atomic: background
// pollAuthoritative goroutines from concurrent tests read the same hook.
func SetAuthoritativeProbe(fn func(ctx context.Context, log *slog.Logger, domain, host string) (resolver.Records, bool)) (restore func()) {
	prev := authoritativeProbe.Load()
	next := probeFunc(fn)
	authoritativeProbe.Store(&next)
	return func() { authoritativeProbe.Store(prev) }
}
