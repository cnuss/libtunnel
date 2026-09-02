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

// specEnvelope is the wire form of v1.SpecEnv: the backend name plus the
// backend's own spec encoding.
type specEnvelope struct {
	Backend string `json:"backend"`
	// Hostname mirrors the spec's public hostname at the envelope level so a
	// reader (Hosts) can list it without knowing the backend's spec type.
	// Redundant with the spec body; decoders that want the credential read Spec.
	Hostname string          `json:"hostname,omitempty"`
	Spec     json.RawMessage `json:"spec"`
}

// selfExported records v1.SpecEnv values this process exported itself, so
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
	// Best effort: a marshal/setenv failure shouldn't fail the tunnel. Only
	// the mint path lands here — adopted specs are not re-exported.
	_ = ExportSpec(p.backend, minted)
	return minted, nil
}

// EncodeSpec returns spec as a tagged-envelope JSON string — the value carried
// by v1.SpecEnv and returned by Spec.Serialize. backend tags which engine minted
// it so a decoder routes to the right spec type.
func EncodeSpec[T v1.Spec](backend string, spec T) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("unable to encode spec: %w", err)
	}
	envelope, err := json.Marshal(specEnvelope{Backend: backend, Hostname: spec.GetHostname(), Spec: data})
	if err != nil {
		return "", fmt.Errorf("unable to encode spec envelope: %w", err)
	}
	return string(envelope), nil
}

// DecodeSpec splits an envelope (EncodeSpec output / v1.SpecEnv value) into its
// backend tag and the raw backend spec JSON, for a caller to unmarshal into the
// matching spec type. A value with no backend tag is not an envelope.
func DecodeSpec(envelope string) (backend string, spec json.RawMessage, err error) {
	var e specEnvelope
	if err := json.Unmarshal([]byte(envelope), &e); err != nil {
		return "", nil, err
	}
	if e.Backend == "" {
		return "", nil, fmt.Errorf("no backend tag (not a spec envelope)")
	}
	return e.Backend, e.Spec, nil
}

// SpecEnviron encodes spec as a "LIBTUNNEL_SPEC=<json>" entry for a child
// process's exec.Cmd.Env, tagged with the minting backend's name.
func SpecEnviron[T v1.Spec](backend string, spec T) (string, error) {
	value, err := EncodeSpec(backend, spec)
	if err != nil {
		return "", err
	}
	return v1.SpecEnv + "=" + value, nil
}

// ExportSpec publishes spec into this process's own environment so re-exec'd
// or spawned children inherit it. The exported value is remembered and never
// re-adopted by this process's own SpecFromEnv (see Env). It also sets
// v1.HostnameEnv to the spec's plain hostname as a convenience mirror.
func ExportSpec[T v1.Spec](backend string, spec T) error {
	entry, err := SpecEnviron(backend, spec)
	if err != nil {
		return err
	}
	value := entry[len(v1.SpecEnv)+1:]
	selfExportedMu.Lock()
	selfExported[value] = true
	selfExportedMu.Unlock()
	if err := os.Setenv(v1.SpecEnv, value); err != nil {
		return err
	}
	// Best effort: the hostname mirror is convenience only, not the channel
	// libtunnel adopts, so a failure here shouldn't fail the export.
	_ = os.Setenv(v1.HostnameEnv, spec.GetHostname())
	return nil
}

// SpecFromEnv decodes LIBTUNNEL_SPEC into the caller-allocated spec. It reports
// whether a spec was adopted; a present-but-malformed value, or one minted by
// a different backend, is an error. A value this process exported itself
// (ExportSpec) reads as absent — the handoff channel carries parent→child
// inheritance only.
func SpecFromEnv[T v1.Spec](backend string, spec T) (bool, error) {
	env, ok := os.LookupEnv(v1.SpecEnv)
	if !ok || env == "" {
		return false, nil
	}

	selfExportedMu.Lock()
	self := selfExported[env]
	selfExportedMu.Unlock()
	if self {
		return false, nil
	}

	tag, raw, err := DecodeSpec(env)
	if err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", v1.SpecEnv, err)
	}
	if tag != backend {
		return false, fmt.Errorf("%s was minted by backend %q, not %q", v1.SpecEnv, tag, backend)
	}
	if err := json.Unmarshal(raw, spec); err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", v1.SpecEnv, err)
	}
	return true, nil
}
