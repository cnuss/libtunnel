package v1alpha1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	v1 "github.com/cnuss/libtunnel/v1"
)

// SpecEnv is the environment variable carrying a JSON-encoded spec across a
// process boundary — the parent→child handoff channel. A parent process mints
// a tunnel spec and exports it (ExportSpec / SpecEnviron); a child process
// adopts it through Env and connects with the same hostname and credentials.
const SpecEnv = "TUNNEL_SPEC"

// assertSpec is a minimal v1.Spec used only by the compile-time interface
// assertions below — this package cannot import a real backend's spec type
// without creating a cycle.
type assertSpec struct{}

func (*assertSpec) GetHostname() string { return "" }

var (
	_ v1.Spec                  = (*assertSpec)(nil)
	_ v1.Provider[*assertSpec] = staticProvider[*assertSpec]{}
	_ v1.Provider[*assertSpec] = envProvider[assertSpec, *assertSpec]{}
)

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

// Env wraps a provider with TUNNEL_SPEC handling: when the environment
// carries a spec, it wins; otherwise the wrapped provider resolves one and
// the result is exported back into this process's environment, so spawned
// children inherit the same tunnel identity with no further plumbing. E is
// the concrete spec struct (e.g. cloudflare.Spec) — inferred from the
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

// SetLogger forwards the tunnel's logger to the wrapped provider.
func (p envProvider[E, T]) SetLogger(log *slog.Logger) {
	if pl, ok := p.next.(interface{ SetLogger(*slog.Logger) }); ok {
		pl.SetLogger(log)
	}
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

	minted, err := p.next.Spec(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	// Export the freshly minted spec so children of this process inherit it.
	// Best effort: a marshal/setenv failure shouldn't fail the tunnel.
	_ = ExportSpec(minted)
	return minted, nil
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
