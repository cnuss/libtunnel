package cloudflare_test

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// TestWithListenerRejectsMalformedSpecID pins the fail-fast contract: a spec
// whose ID is not a UUID (e.g. a corrupted TUNNEL_SPEC handoff) must cancel
// the tunnel with a descriptive cause instead of registering the zero UUID
// with the edge. Runs offline — the ID check fires before any network use.
func TestWithListenerRejectsMalformedSpecID(t *testing.T) {
	t.Setenv("TUNNEL_SPEC", `{"backend":"cloudflare","spec":{"id":"not-a-uuid","hostname":"x.trycloudflare.com","account_tag":"tag","secret":"c2VjcmV0"}}`)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	conn := v1alpha1.New(cloudflare.New()).WithListener(l)
	select {
	case <-conn.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel did not fail on a malformed spec id")
	}
	if err := conn.Err(); err == nil || !strings.Contains(err.Error(), "invalid tunnel id") {
		t.Errorf("Err() = %v, want an invalid tunnel id cause", err)
	}
}
