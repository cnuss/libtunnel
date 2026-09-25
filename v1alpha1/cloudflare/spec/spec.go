// Package spec is the Cloudflare backend's credential set, on its own so
// that everything under v1alpha1/cloudflare can name it without importing
// the engine.
package spec

import (
	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// Backend is the tag a Cloudflare spec serialises under: the name the
// backend reports, and the envelope's tag in the LIBTUNNEL_SPEC handoff, so
// a child running a different backend fails loudly.
const Backend = "cloudflare"

// Spec is the Cloudflare backend's credential set — the spec type T produced
// by libtunnel.Cloudflare(). The json tags match the tunnel.pizza
// response and the LIBTUNNEL_SPEC handoff encoding.
type Spec struct {
	// RecordID resumes a hostname: the provider's handle on the DNS record
	// that reserves it, returned by the mint and replayed to it. It is a
	// bearer credential — replaying it yields the secret — and it is what
	// keeps a retry from minting a second tunnel.
	RecordID   string `json:"record_id,omitempty"`
	ID         string `json:"id"`
	Name       string `json:"name"`
	Hostname   string `json:"hostname"`
	AccountTag string `json:"account_tag"`
	Secret     []byte `json:"secret"`
}

var _ v1.Spec = (*Spec)(nil)

// GetHostname implements v1.Spec.
func (s *Spec) GetHostname() string {
	if s == nil {
		return ""
	}
	return s.Hostname
}

// Serialize implements v1.Spec: the tagged-envelope JSON for this spec, tagged
// "cloudflare" — the same form as LIBTUNNEL_SPEC, so it round-trips through
// libtunnel.From.
func (s *Spec) Serialize() string {
	out, err := v1alpha1.EncodeSpec(Backend, s)
	if err != nil {
		return ""
	}
	return out
}
