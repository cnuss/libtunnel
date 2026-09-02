package v1alpha1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
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

// Replay wraps next with v1.FromEnv handling for the named backend: when the
// environment references a spec, it is loaded and replayed — superseding
// next, even a code-pinned From spec; env beats code. A reference that
// cannot be parsed, carries a foreign backend tag, or fails to decode is an
// error, not a fallthrough. Unset, next resolves as usual. E is the concrete
// spec struct, inferred like Env's.
func Replay[E any, T interface {
	*E
	v1.Spec
}](backend string, next v1.Provider[T]) v1.Provider[T] {
	return replayProvider[E, T]{backend: backend, next: next}
}

type replayProvider[E any, T interface {
	*E
	v1.Spec
}] struct {
	backend string
	next    v1.Provider[T]
}

// SetLogger forwards the tunnel's logger to the wrapped provider.
func (p replayProvider[E, T]) SetLogger(log *slog.Logger) {
	if pl, ok := p.next.(LoggerSetter); ok {
		pl.SetLogger(log)
	}
}

func (p replayProvider[E, T]) Spec(ctx context.Context) (T, error) {
	env, ok := os.LookupEnv(v1.FromEnv)
	if !ok || env == "" {
		return p.next.Spec(ctx)
	}

	var zero T
	tag, raw, err := DecodeSpec(loadSpec(env))
	if err != nil {
		return zero, fmt.Errorf("unable to parse %s: %w", v1.FromEnv, err)
	}
	if tag != p.backend {
		return zero, fmt.Errorf("%s references a spec minted by backend %q, not %q", v1.FromEnv, tag, p.backend)
	}
	spec := T(new(E))
	if err := json.Unmarshal(raw, spec); err != nil {
		return zero, fmt.Errorf("unable to parse %s: %w", v1.FromEnv, err)
	}
	return spec, nil
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
