package v1alpha1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	Backend string `json:"backend"`
	// Hostname mirrors the spec's public hostname at the envelope level so a
	// reader (Hosts) can list it without knowing the backend's spec type.
	// Redundant with the spec body; decoders that want the credential read Spec.
	Hostname string          `json:"hostname,omitempty"`
	Spec     json.RawMessage `json:"spec"`
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
	// Export the freshly minted spec so children of this process inherit it,
	// and cache it to disk for later replay via libtunnel.From. Both best
	// effort: a marshal/setenv/write failure shouldn't fail the tunnel. Only
	// the mint path lands here — adopted specs are not re-exported or re-cached.
	_ = ExportSpec(p.backend, minted)
	_ = cacheSpec(minted)
	return minted, nil
}

// EncodeSpec returns spec as a tagged-envelope JSON string — the value carried
// by SpecEnv and returned by Spec.Serialize. backend tags which engine minted
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

// DecodeSpec splits an envelope (EncodeSpec output / SpecEnv value) into its
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
	return SpecEnv + "=" + value, nil
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

	tag, raw, err := DecodeSpec(env)
	if err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", SpecEnv, err)
	}
	if tag != backend {
		return false, fmt.Errorf("%s was minted by backend %q, not %q", SpecEnv, tag, backend)
	}
	if err := json.Unmarshal(raw, spec); err != nil {
		return false, fmt.Errorf("unable to parse %s: %w", SpecEnv, err)
	}
	return true, nil
}

// CacheDirEnv overrides where specs are cached and looked up (cache write,
// Hosts, From). Unset, the per-user os.UserCacheDir()/libtunnel is used.
const CacheDirEnv = "LIBTUNNEL_CACHE_DIR"

// CacheDir is the directory specs are cached to and replayed from: CacheDirEnv
// when set (used as-is), otherwise os.UserCacheDir() namespaced by the stable
// v1 contract package path (e.g. .../github.com/cnuss/libtunnel/v1).
func CacheDir() (string, error) {
	if d := os.Getenv(CacheDirEnv); d != "" {
		return d, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, filepath.FromSlash(packagePath())), nil
}

// packagePath is the stable contract package path
// (github.com/cnuss/libtunnel/v1), inferred via reflection on v1.Spec rather
// than hardcoded — so a fork or rename gets its own cache namespace, and the
// namespace tracks the stable v1 surface instead of drifting with each alpha.
func packagePath() string {
	return reflect.TypeOf((*v1.Spec)(nil)).Elem().PkgPath()
}

// cacheSpec writes a freshly minted spec to CacheDir as <hostname>.spec.json
// (Serialize output, the SpecEnv envelope). Best effort: callers ignore the
// error — the cache is a convenience, not the source of truth. Only minted
// specs are cached (see envProvider.Spec); adopted or From-loaded specs are
// not re-written.
func cacheSpec[T v1.Spec](spec T) error {
	host := spec.GetHostname()
	if host == "" {
		return nil // nothing to key the file on
	}
	dir, err := CacheDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := cacheFileName(host)
	return os.WriteFile(filepath.Join(dir, name), []byte(spec.Serialize()), 0o600)
}

// cacheFileName builds a filesystem-safe "<hostname>.spec.json": GetHostname
// may carry a :port, and the colon (plus any separators) is illegal in a
// filename on some platforms.
func cacheFileName(hostname string) string {
	safe := strings.NewReplacer("/", "_", `\`, "_", ":", "_").Replace(hostname)
	return safe + ".spec.json"
}
