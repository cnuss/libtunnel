package spec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cnuss/libtunnel/v1alpha1"
)

// TestRecordIDRidesTheEnvelopeNotTheSpec pins where the record goes: the
// spec's own encoding is the provider's result and nothing more, the record
// sits beside it under "metadata", and a decode puts it back on the spec.
// It is what a replay resumes the hostname by, so a handoff or a cache that
// dropped it would mint a second tunnel.
func TestRecordIDRidesTheEnvelopeNotTheSpec(t *testing.T) {
	s := &Spec{ID: "id-1", Name: "n", Hostname: "h.tunneled.pizza", AccountTag: "tag", Secret: []byte("s")}
	s.WithMeta(RecordIDKey, "rec-1")
	s.WithMessage("data:text/markdown;base64,PiBbIW5vdGVdIGhp")
	envelope := s.Serialize()
	if envelope == "" {
		t.Fatal("Serialize returned nothing")
	}

	var e struct {
		Spec     map[string]json.RawMessage `json:"spec"`
		Metadata map[string]string          `json:"metadata"`
		Messages []string                   `json:"messages"`
	}
	if err := json.Unmarshal([]byte(envelope), &e); err != nil {
		t.Fatal(err)
	}
	if _, inSpec := e.Spec["record_id"]; inSpec {
		t.Errorf("record_id inside the spec body; want it beside it: %s", envelope)
	}
	if e.Metadata["record_id"] != "rec-1" {
		t.Errorf("metadata.record_id = %q, want rec-1: %s", e.Metadata["record_id"], envelope)
	}
	if len(e.Messages) != 1 || e.Messages[0] != s.Messages()[0] {
		t.Errorf("messages = %q, want the one as sent: %s", e.Messages, envelope)
	}

	backend, raw, aside, err := v1alpha1.DecodeSpec(envelope)
	if err != nil || backend != Backend {
		t.Fatalf("DecodeSpec = %q, %v", backend, err)
	}
	got := &Spec{}
	if err := v1alpha1.Unpack(raw, aside, got); err != nil {
		t.Fatal(err)
	}
	if got.RecordID() != "rec-1" || got.ID != "id-1" || got.Hostname != s.Hostname {
		t.Errorf("round trip = %+v record %q, want the spec back with its record", got, got.RecordID())
	}
	if len(got.Messages()) != 1 || got.Messages()[0] != s.Messages()[0] {
		t.Errorf("round trip messages = %q, want %q", got.Messages(), s.Messages())
	}
}

// TestNoRecordIDWritesNoMetadata pins that a spec with nothing beside it
// serializes without a metadata key at all, and decodes the same.
func TestNoRecordIDWritesNoMetadata(t *testing.T) {
	s := &Spec{ID: "id-1", Hostname: "h.tunneled.pizza"}
	envelope := s.Serialize()
	if strings.Contains(envelope, "metadata") || strings.Contains(envelope, "messages") {
		t.Errorf("envelope carries something beside a spec that has nothing: %s", envelope)
	}
	_, raw, aside, err := v1alpha1.DecodeSpec(envelope)
	if err != nil {
		t.Fatal(err)
	}
	got := &Spec{}
	if err := v1alpha1.Unpack(raw, aside, got); err != nil {
		t.Fatal(err)
	}
	if got.RecordID() != "" || got.Messages() != nil {
		t.Errorf("record %q, messages %v, want none", got.RecordID(), got.Messages())
	}
}

// TestUnknownMetadataIsDropped pins the best effort: the interface speaks in
// keys, Meta is typed, and a key this backend has no field for is neither
// kept nor carried on — only what Meta knows comes back out of Metadata.
func TestUnknownMetadataIsDropped(t *testing.T) {
	s := &Spec{ID: "id-1", Hostname: "h.tunneled.pizza"}
	s.WithMeta("x-something-else", "v")
	if got := s.Metadata(); got != nil {
		t.Errorf("Metadata = %v after an unknown key, want nil", got)
	}
	s.WithMeta(RecordIDKey, "rec-1")
	if got := s.Metadata(); len(got) != 1 || got[RecordIDKey] != "rec-1" {
		t.Errorf("Metadata = %v, want only the record", got)
	}
}
