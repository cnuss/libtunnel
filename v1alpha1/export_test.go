package v1alpha1

import (
	"time"
)

// SetSettleDelay replaces how long readiness waits after the edge connection
// registers, and returns a function restoring the previous delay. Tests set
// zero to make readiness immediate and something enormous to hold it open.
// The swap is atomic: background start goroutines from concurrent tests read
// the same value.
func SetSettleDelay(d time.Duration) (restore func()) {
	prev := settleDelay.Swap(int64(d))
	return func() { settleDelay.Store(prev) }
}
