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

// RecordIDKey names, in a spec's metadata, the provider's handle on the DNS
// record that reserves its hostname: returned by the mint as X-Record-Id and
// replayed to it the same way. It is a bearer credential — replaying it
// yields the secret — and it is what keeps a retry from minting a second
// tunnel.
const RecordIDKey = "record_id"

// Meta is what tunnel.pizza said beside the spec, typed. The interface speaks
// in keys (v1.SpecMetadata); they are filled in here and read out from here,
// best effort — a key this backend does not know is dropped on the way in,
// and a field it has nothing for is left out on the way out. Messages are
// carried as sent.
type Meta struct {
	recordID string
	messages []string
}

// Spec is the Cloudflare backend's credential set — the spec type T produced
// by libtunnel.Cloudflare(). The json tags match the tunnel.pizza
// response's result exactly; what came beside it is Meta.
type Spec struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Hostname   string `json:"hostname"`
	AccountTag string `json:"account_tag"`
	Secret     []byte `json:"secret"`

	meta Meta
}

var _ v1.Spec = (*Spec)(nil)

// Metadata implements v1.Spec: Meta, under its keys. Nil when there is
// nothing in it.
func (s *Spec) Metadata() v1.SpecMetadata {
	if s == nil || s.meta.recordID == "" {
		return nil
	}
	return v1.SpecMetadata{RecordIDKey: s.meta.recordID}
}

// WithMeta implements v1.Spec: a key this backend knows lands in Meta, any
// other is dropped.
func (s *Spec) WithMeta(key, value string) v1.Spec {
	switch key {
	case RecordIDKey:
		s.meta.recordID = value
	}
	return s
}

// Messages implements v1.Spec.
func (s *Spec) Messages() []string {
	if s == nil {
		return nil
	}
	return s.meta.messages
}

// WithMessage implements v1.Spec.
func (s *Spec) WithMessage(message string) v1.Spec {
	s.meta.messages = append(s.meta.messages, message)
	return s
}

// RecordID is the provider's handle on the hostname's record (RecordIDKey),
// or "" when the spec has none to replay.
func (s *Spec) RecordID() string {
	if s == nil {
		return ""
	}
	return s.meta.recordID
}

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
