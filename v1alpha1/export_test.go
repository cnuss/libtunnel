package v1alpha1

import (
	"time"

	"github.com/cnuss/libtunnel/v1alpha1/resolver"
)

// SetResolver substitutes the resolver used for hostname readiness and returns
// a function restoring the previous one. It lets readiness resolve without a
// network — the real resolvers are exercised by their own package's tests and
// by the live e2e suite. The swap is atomic: background start goroutines from
// concurrent tests read the same hook.
func SetResolver(r resolver.Resolver) (restore func()) {
	prev := newResolver.Load()
	next := resolverFactory(func() resolver.Resolver { return r })
	newResolver.Store(&next)
	return func() { newResolver.Store(prev) }
}

// SetResolveTimeout shortens how long readiness waits for the hostname to
// resolve and returns a function restoring the previous bound, so a test can
// reach the give-up path in milliseconds rather than the production minute.
func SetResolveTimeout(d time.Duration) (restore func()) {
	prev := resolveTimeout.Swap(int64(d))
	return func() { resolveTimeout.Store(prev) }
}
