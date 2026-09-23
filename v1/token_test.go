package v1_test

import (
	"testing"

	v1 "github.com/cnuss/libtunnel/v1"
)

// TestTokenFallsBackToTheActionsToken pins the order the mint credential is
// read in. The fallback exists because a CI runner's address is shared and
// lands on DNS blocklists, so a provider that screens by address turns down
// honest runs; the token it can be judged by instead is one GitHub already
// issues. An explicit LIBTUNNEL_TOKEN still wins — the fallback is for
// callers who set nothing, not a value that overrides what they did set.
func TestTokenFallsBackToTheActionsToken(t *testing.T) {
	for _, tc := range []struct {
		name    string
		token   string
		actions string
		want    string
	}{
		{"neither set", "", "", ""},
		{"only the mirror", "mint", "", "mint"},
		{"only the actions token", "", "runtime", "runtime"},
		{"the mirror wins", "mint", "runtime", "mint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(v1.TokenEnv, tc.token)
			t.Setenv(v1.ActionsTokenEnv, tc.actions)
			if got := v1.Token(); got != tc.want {
				t.Errorf("Token() = %q, want %q", got, tc.want)
			}
		})
	}
}
