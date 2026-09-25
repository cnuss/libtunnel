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
	Aside
}

// Aside is what the envelope carries beside the spec, kept out of the spec's
// own encoding so that stays the provider's: what the provider said in its
// headers (v1.Spec.Metadata) and what it said to whoever runs this
// (v1.Spec.Messages). Each absent when there was nothing.
type Aside struct {
	Metadata v1.SpecMetadata `json:"metadata,omitempty"`
	Messages []string        `json:"messages,omitempty"`
}

// selfExported records v1.SpecEnv values this process exported itself, so
// SpecFromEnv never hands them back: the handoff is parent→child inheritance,
// not tunnel→tunnel within a process. Without this, a second in-process
// tunnel would take the first tunnel's identity as its hint the moment its
// mint exported, and ask the provider for the same tunnel.
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

// Export wraps a provider so the spec it resolves is published into this
// process's environment as LIBTUNNEL_SPEC, and spawned children inherit the
// same tunnel identity with no further plumbing. Every resolution is
// exported, adopted or minted, so a child's own children get what this
// process resolved.
func Export[T v1.Spec](backend string, next v1.Provider[T]) v1.Provider[T] {
	return exportProvider[T]{backend: backend, next: next}
}

type exportProvider[T v1.Spec] struct {
	backend string
	next    v1.Provider[T]
}

// SetLogger forwards the tunnel's logger to the wrapped provider.
func (p exportProvider[T]) SetLogger(log *slog.Logger) {
	if pl, ok := p.next.(LoggerSetter); ok {
		pl.SetLogger(log)
	}
}

func (p exportProvider[T]) Spec(ctx context.Context) (T, error) {
	spec, err := p.next.Spec(ctx)
	if err != nil {
		var zero T
		return zero, err
	}
	// Best effort: a marshal/setenv failure shouldn't fail the tunnel.
	_ = ExportSpec(p.backend, spec)
	return spec, nil
}

// EncodeSpec returns spec as a tagged-envelope JSON string — the value carried
// by v1.SpecEnv and returned by Spec.Serialize. backend tags which engine minted
// it so a decoder routes to the right spec type.
func EncodeSpec[T v1.Spec](backend string, spec T) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("unable to encode spec: %w", err)
	}
	envelope, err := json.Marshal(specEnvelope{
		Backend:  backend,
		Hostname: spec.GetHostname(),
		Spec:     data,
		Aside:    Aside{Metadata: spec.Metadata(), Messages: spec.Messages()},
	})
	if err != nil {
		return "", fmt.Errorf("unable to encode spec envelope: %w", err)
	}
	return string(envelope), nil
}

// DecodeSpec splits an envelope (EncodeSpec output / v1.SpecEnv value) into
// its backend tag, the raw backend spec JSON and what rode beside it, for a
// caller to unpack into the matching spec type. A value with no backend tag
// is not an envelope.
func DecodeSpec(envelope string) (backend string, spec json.RawMessage, aside Aside, err error) {
	var e specEnvelope
	if err := json.Unmarshal([]byte(envelope), &e); err != nil {
		return "", nil, Aside{}, err
	}
	if e.Backend == "" {
		return "", nil, Aside{}, fmt.Errorf("no backend tag (not a spec envelope)")
	}
	return e.Backend, e.Spec, e.Aside, nil
}

// Unpack fills into from what DecodeSpec split: the spec from its own JSON,
// then what rode beside it, the metadata key by key and the messages in
// order.
func Unpack[T v1.Spec](spec json.RawMessage, aside Aside, into T) error {
	if err := json.Unmarshal(spec, into); err != nil {
		return err
	}
	for key, value := range aside.Metadata {
		into.WithMeta(key, value)
	}
	for _, message := range aside.Messages {
		into.WithMessage(message)
	}
	return nil
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
// handed back by this process's own SpecFromEnv (see Export). It also sets
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
	// libtunnel reads, so a failure here shouldn't fail the export.
	_ = os.Setenv(v1.HostnameEnv, spec.GetHostname())
	return nil
}

// SpecFromEnv decodes LIBTUNNEL_SPEC into the caller-allocated spec. It reports
// whether one was present; a present-but-malformed value, or one minted by
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

	tag, raw, aside, err := DecodeSpec(env)
	if err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", v1.SpecEnv, err)
	}
	if tag != backend {
		return false, fmt.Errorf("%s was minted by backend %q, not %q", v1.SpecEnv, tag, backend)
	}
	if err := Unpack(raw, aside, spec); err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", v1.SpecEnv, err)
	}
	return true, nil
}
