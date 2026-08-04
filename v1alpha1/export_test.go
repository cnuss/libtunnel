package v1alpha1

import (
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
