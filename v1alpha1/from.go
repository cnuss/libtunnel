package v1alpha1

import (
	"encoding/json"
	"fmt"
	"os"

	v1 "github.com/cnuss/libtunnel/v1"
)

// From loads a serialized spec and replays it into a tunnel. spec is either a
// path to a spec file (an existing file is read) or the serialized JSON itself.
// It decodes the envelope and hands the backend tag plus the raw backend spec
// to build, which constructs the tunnel for that backend — the one piece From
// can't own, since v1alpha1 is backend-agnostic and the façade wires the
// concrete backend. Any failure (unreadable, unparseable, unknown backend, or a
// build error) returns a tunnel already canceled with the cause, so callers get
// it through Err()/Done() rather than a second return value.
func From(spec string, build func(backend string, raw json.RawMessage) (v1.Tunnel, error)) v1.Tunnel {
	value := spec
	if data, err := os.ReadFile(spec); err == nil {
		value = string(data)
	}

	backend, raw, err := DecodeSpec(value)
	if err != nil {
		return Failed(fmt.Errorf("From: %w", err))
	}
	tun, err := build(backend, raw)
	if err != nil {
		return Failed(fmt.Errorf("From: %w", err))
	}
	return tun
}

// Failed returns a tunnel already canceled with cause — for façade entry points
// (e.g. libtunnel.From) that detect bad input and report it through the
// Err()/Done() channel instead of a second return value. It has no backend, so
// every getter resolves to its zero value.
func Failed(cause error) v1.Tunnel {
	t := newImpl[v1.Spec](nil)
	t.cancel(cause)
	return t
}
