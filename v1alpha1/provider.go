package v1alpha1

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	v1 "github.com/cnuss/libtunnel/v1"
)

// SpecEnv is the environment variable carrying a JSON-encoded spec across a
// process boundary — the parent→child handoff channel. A parent process mints
// a tunnel spec and exports it (ExportSpec / SpecEnviron); a child process
// adopts it through Env and connects with the same hostname and credentials.
const SpecEnv = "TUNNEL_SPEC"

// Static returns a provider that yields the given spec verbatim. Useful for
// replaying known credentials (tests, fixed tunnels).
func Static[T v1.Spec](spec T) v1.Provider[T] {
	return staticProvider[T]{spec: spec}
}

type staticProvider[T v1.Spec] struct {
	spec T
}

func (p staticProvider[T]) Spec(context.Context) (T, error) {
	return p.spec, nil
}

// Env wraps a provider with TUNNEL_SPEC adoption: when the environment
// carries a spec, it wins; otherwise the wrapped provider resolves one. E is
// the concrete spec struct (e.g. v1.CloudflareSpec) — inferred from the
// wrapped provider's *E spec type.
func Env[E any, T interface {
	*E
	v1.Spec
}](next v1.Provider[T]) v1.Provider[T] {
	return envProvider[E, T]{next: next}
}

type envProvider[E any, T interface {
	*E
	v1.Spec
}] struct {
	next v1.Provider[T]
}

func (p envProvider[E, T]) Spec(ctx context.Context) (T, error) {
	spec := T(new(E))
	ok, err := SpecFromEnv(spec)
	if err != nil {
		var zero T
		return zero, err
	}
	if ok {
		return spec, nil
	}
	return p.next.Spec(ctx)
}

// SpecEnviron encodes spec as a "TUNNEL_SPEC=<json>" entry for a child
// process's exec.Cmd.Env.
func SpecEnviron[T v1.Spec](spec T) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("unable to encode spec: %w", err)
	}
	return SpecEnv + "=" + string(data), nil
}

// ExportSpec publishes spec into this process's own environment so re-exec'd
// or spawned children inherit it.
func ExportSpec[T v1.Spec](spec T) error {
	data, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("unable to encode spec: %w", err)
	}
	return os.Setenv(SpecEnv, string(data))
}

// SpecFromEnv decodes TUNNEL_SPEC into the caller-allocated spec. It reports
// whether the variable was present; a present-but-malformed value is an
// error.
func SpecFromEnv[T v1.Spec](spec T) (bool, error) {
	env, ok := os.LookupEnv(SpecEnv)
	if !ok || env == "" {
		return false, nil
	}
	if err := json.Unmarshal([]byte(env), spec); err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", SpecEnv, err)
	}
	return true, nil
}
