package v1alpha1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	v1 "github.com/cnuss/libtunnel/v1"
)

// SpecEnv is the environment variable carrying a JSON-encoded spec across a
// process boundary — the parent→child handoff channel. A parent process mints
// a tunnel spec and exports it (ExportSpec / SpecEnviron); a child process
// adopts it through Env and connects with the same hostname and credentials.
// The value is a specEnvelope: the spec tagged with the backend that minted
// it, so a child running a different backend fails loudly instead of
// unmarshaling a foreign spec into its own type.
const SpecEnv = "LIBTUNNEL_SPEC"

// HostnameEnv is a plain-text mirror of the spec's hostname, set by ExportSpec
// alongside SpecEnv. It is export-only convenience — tooling or a child process
// can read the public hostname without parsing the SpecEnv envelope. libtunnel
// itself never adopts it: connecting needs the full credential in SpecEnv, not
// a hostname alone.
const HostnameEnv = "LIBTUNNEL_HOSTNAME"

// specEnvelope is the wire form of SpecEnv: the backend name plus the
// backend's own spec encoding.
type specEnvelope struct {
	Backend string          `json:"backend"`
	Spec    json.RawMessage `json:"spec"`
}

// selfExported records SpecEnv values this process exported itself, so
// SpecFromEnv never re-adopts them: the handoff is parent→child inheritance,
// not tunnel→tunnel within a process. Without this, a second in-process
// tunnel would race to adopt the first tunnel's identity the moment its mint
// exported, putting two connectors behind one hostname.
var (
	selfExportedMu sync.Mutex
	selfExported   = map[string]bool{}
)

// LoggerSetter is the optional provider capability the tunnel core probes to
// thread its logger into providers that can log (retry warnings, rate
// limits). Provider wrappers must forward SetLogger to what they wrap, or
// logging is silently severed for everything beneath them.
type LoggerSetter interface {
	SetLogger(*slog.Logger)
}

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

// Env wraps a provider with LIBTUNNEL_SPEC handling for the named backend: when
// the environment carries a spec inherited from a parent process, it wins;
// otherwise the wrapped provider resolves one and the result is exported back
// into this process's environment, so spawned children inherit the same
// tunnel identity with no further plumbing. A spec this process exported
// itself is never re-adopted — a second in-process tunnel mints its own
// identity. E is the concrete spec struct (e.g. cloudflare.Spec) — inferred
// from the wrapped provider's *E spec type.
func Env[E any, T interface {
	*E
	v1.Spec
}](backend string, next v1.Provider[T]) v1.Provider[T] {
	return envProvider[E, T]{backend: backend, next: next}
}

type envProvider[E any, T interface {
	*E
	v1.Spec
}] struct {
	backend string
	next    v1.Provider[T]
}

// SetLogger forwards the tunnel's logger to the wrapped provider.
func (p envProvider[E, T]) SetLogger(log *slog.Logger) {
	if pl, ok := p.next.(LoggerSetter); ok {
		pl.SetLogger(log)
	}
}

func (p envProvider[E, T]) Spec(ctx context.Context) (T, error) {
	spec := T(new(E))
	ok, err := SpecFromEnv(p.backend, spec)
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
	_ = ExportSpec(p.backend, minted)
	return minted, nil
}

// SpecEnviron encodes spec as a "LIBTUNNEL_SPEC=<json>" entry for a child
// process's exec.Cmd.Env, tagged with the minting backend's name.
func SpecEnviron[T v1.Spec](backend string, spec T) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("unable to encode spec: %w", err)
	}
	envelope, err := json.Marshal(specEnvelope{Backend: backend, Spec: data})
	if err != nil {
		return "", fmt.Errorf("unable to encode spec envelope: %w", err)
	}
	return SpecEnv + "=" + string(envelope), nil
}

// ExportSpec publishes spec into this process's own environment so re-exec'd
// or spawned children inherit it. The exported value is remembered and never
// re-adopted by this process's own SpecFromEnv (see Env). It also sets
// HostnameEnv to the spec's plain hostname as a convenience mirror.
func ExportSpec[T v1.Spec](backend string, spec T) error {
	entry, err := SpecEnviron(backend, spec)
	if err != nil {
		return err
	}
	value := entry[len(SpecEnv)+1:]
	selfExportedMu.Lock()
	selfExported[value] = true
	selfExportedMu.Unlock()
	if err := os.Setenv(SpecEnv, value); err != nil {
		return err
	}
	// Best effort: the hostname mirror is convenience only, not the channel
	// libtunnel adopts, so a failure here shouldn't fail the export.
	_ = os.Setenv(HostnameEnv, spec.GetHostname())
	return nil
}

// SpecFromEnv decodes LIBTUNNEL_SPEC into the caller-allocated spec. It reports
// whether a spec was adopted; a present-but-malformed value, or one minted by
// a different backend, is an error. A value this process exported itself
// (ExportSpec) reads as absent — the handoff channel carries parent→child
// inheritance only.
func SpecFromEnv[T v1.Spec](backend string, spec T) (bool, error) {
	env, ok := os.LookupEnv(SpecEnv)
	if !ok || env == "" {
		return false, nil
	}

	selfExportedMu.Lock()
	self := selfExported[env]
	selfExportedMu.Unlock()
	if self {
		return false, nil
	}

	var envelope specEnvelope
	if err := json.Unmarshal([]byte(env), &envelope); err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", SpecEnv, err)
	}
	if envelope.Backend == "" {
		return false, fmt.Errorf("unable to parse %s: no backend tag (not a spec envelope)", SpecEnv)
	}
	if envelope.Backend != backend {
		return false, fmt.Errorf("%s was minted by backend %q, not %q", SpecEnv, envelope.Backend, backend)
	}
	if err := json.Unmarshal(envelope.Spec, spec); err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", SpecEnv, err)
	}
	return true, nil
}
