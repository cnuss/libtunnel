package v1alpha1

import (
	"encoding/json"
	"fmt"
	"os"

	v1 "github.com/cnuss/libtunnel/v1"
)

// From loads a serialized spec and replays it into a tunnel. spec is resolved
// as an existing file at the given path, otherwise as the literal JSON. It
// decodes the envelope and hands
// the backend tag plus the raw backend spec to build, which constructs the
// tunnel for that backend — the one piece From can't own, since v1alpha1 is
// backend-agnostic and the façade wires the concrete backend. Any failure
// (unparseable, unknown backend, or a build error) returns a tunnel already
// canceled with the cause, so callers get it through Err()/Done() rather than a
// second return value.
func From(spec string, build func(backend string, raw json.RawMessage) (v1.Tunnel, error)) v1.Tunnel {
	backend, raw, err := DecodeSpec(loadSpec(spec))
	if err != nil {
		return Failed(fmt.Errorf("From: %w", err))
	}
	tun, err := build(backend, raw)
	if err != nil {
		return Failed(fmt.Errorf("From: %w", err))
	}
	return tun
}

// ReplayFromEnv decodes v1.FromEnv — a spec file path or a literal envelope,
// like From's argument — into the caller-allocated spec, reporting whether
// one was present. A reference that cannot be parsed, or carries a foreign
// backend tag, is an error, not a fallthrough.
func ReplayFromEnv[T v1.Spec](backend string, spec T) (bool, error) {
	env, ok := os.LookupEnv(v1.FromEnv)
	if !ok || env == "" {
		return false, nil
	}
	tag, raw, err := DecodeSpec(loadSpec(env))
	if err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", v1.FromEnv, err)
	}
	if tag != backend {
		return false, fmt.Errorf("%s references a spec minted by backend %q, not %q", v1.FromEnv, tag, backend)
	}
	if err := json.Unmarshal(raw, spec); err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", v1.FromEnv, err)
	}
	return true, nil
}

// loadSpec turns the From argument into the serialized envelope: an existing
// file at the given path, else the argument verbatim (a literal JSON
// envelope).
func loadSpec(spec string) string {
	if data, err := os.ReadFile(spec); err == nil {
		return string(data)
	}
	return spec
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
