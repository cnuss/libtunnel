package spec

import (
	"encoding/json"
	"net/http"
	"reflect"
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
	if strings.Contains(envelope, "metadata") || strings.Contains(envelope, "messages") || strings.Contains(envelope, "headers") {
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
	if got.RecordID() != "" || got.Messages() != nil || got.Headers() != nil {
		t.Errorf("record %q, messages %v, headers %v, want none", got.RecordID(), got.Messages(), got.Headers())
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

// TestHeadersRideTheEnvelopeUnfiltered pins where a mint's response headers
// go: beside the spec under "headers", every one of them and every value in
// order, X-Record-Id included, and back onto the spec on a decode. The
// record's own metadata is a separate carrier and is not touched by them.
func TestHeadersRideTheEnvelopeUnfiltered(t *testing.T) {
	s := &Spec{ID: "id-1", Hostname: "h.tunneled.pizza", Secret: []byte("s")}
	s.WithResponseHeader("x-record-id", "rec-1")
	s.WithResponseHeader("X-Www-Authenticate", `Basic realm="h.tunneled.pizza", pw="$pbkdf2-sha256$i=600000$c2FsdA$aGFzaA"`)
	s.WithResponseHeader("Date", "Sun, 04 Oct 2026 23:30:00 GMT")
	s.WithResponseHeader("X-Twice", "one")
	s.WithResponseHeader("X-Twice", "two")

	envelope := s.Serialize()
	var e struct {
		Spec     map[string]json.RawMessage `json:"spec"`
		Metadata map[string]string          `json:"metadata"`
		Headers  http.Header                `json:"headers"`
	}
	if err := json.Unmarshal([]byte(envelope), &e); err != nil {
		t.Fatal(err)
	}
	if _, inSpec := e.Spec["headers"]; inSpec {
		t.Errorf("headers inside the spec body; want them beside it: %s", envelope)
	}
	want := http.Header{
		"X-Record-Id":        {"rec-1"},
		"X-Www-Authenticate": {`Basic realm="h.tunneled.pizza", pw="$pbkdf2-sha256$i=600000$c2FsdA$aGFzaA"`},
		"Date":               {"Sun, 04 Oct 2026 23:30:00 GMT"},
		"X-Twice":            {"one", "two"},
	}
	if !reflect.DeepEqual(e.Headers, want) {
		t.Errorf("envelope headers = %v, want %v", e.Headers, want)
	}
	if e.Metadata != nil {
		t.Errorf("metadata = %v; a header is not metadata, want none", e.Metadata)
	}

	_, raw, aside, err := v1alpha1.DecodeSpec(envelope)
	if err != nil {
		t.Fatal(err)
	}
	got := &Spec{}
	if err := v1alpha1.Unpack(raw, aside, got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Headers(), want) {
		t.Errorf("round trip headers = %v, want %v", got.Headers(), want)
	}
	if got.RecordID() != "" {
		t.Errorf("RecordID = %q from a header alone, want it only from metadata", got.RecordID())
	}
}

// TestHeadersFromAnOldEnvelope pins that an envelope written before headers
// existed decodes as it always did, with no headers, and that a hand-written
// lowercase key reads back canonical, so Get finds it.
func TestHeadersFromAnOldEnvelope(t *testing.T) {
	old := `{"backend":"cloudflare","hostname":"h.tunneled.pizza","spec":{"id":"id-1","name":"","hostname":"h.tunneled.pizza","account_tag":"","secret":"cw=="},"metadata":{"record_id":"rec-1"}}`
	_, raw, aside, err := v1alpha1.DecodeSpec(old)
	if err != nil {
		t.Fatal(err)
	}
	got := &Spec{}
	if err := v1alpha1.Unpack(raw, aside, got); err != nil {
		t.Fatal(err)
	}
	if got.Headers() != nil || got.RecordID() != "rec-1" {
		t.Errorf("headers %v, record %q; want none and rec-1", got.Headers(), got.RecordID())
	}

	lower := `{"backend":"cloudflare","spec":{"id":"id-1","hostname":"h.tunneled.pizza"},"headers":{"x-www-authenticate":["Basic realm=\"h\""]}}`
	_, raw, aside, err = v1alpha1.DecodeSpec(lower)
	if err != nil {
		t.Fatal(err)
	}
	got = &Spec{}
	if err := v1alpha1.Unpack(raw, aside, got); err != nil {
		t.Fatal(err)
	}
	if v := got.Headers().Get("X-Www-Authenticate"); v != `Basic realm="h"` {
		t.Errorf("Get(X-Www-Authenticate) = %q from a lowercase key, want it canonical", v)
	}
}

// TestHeadersIsACopy pins that what Headers hands out is the caller's: a
// change to it reaches neither the spec nor what it serializes.
func TestHeadersIsACopy(t *testing.T) {
	s := &Spec{ID: "id-1", Hostname: "h.tunneled.pizza"}
	s.WithResponseHeader("X-One", "1")
	h := s.Headers()
	h.Set("X-One", "changed")
	h.Set("X-Two", "2")
	if got := s.Headers(); !reflect.DeepEqual(got, http.Header{"X-One": {"1"}}) {
		t.Errorf("Headers after a caller's change = %v, want the spec's own", got)
	}
	if strings.Contains(s.Serialize(), "changed") {
		t.Error("a caller's change to Headers reached the envelope")
	}
}
