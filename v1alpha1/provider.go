package v1alpha1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"

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

// selfCached is the disk-cache analogue of selfExported: hostnames of specs
// this process cached itself. LatestSpec skips them — without this, a second
// tunnel minted in the same process would read the first tunnel's fresh
// latest.spec.json and reclaim its LIVE tunnel, putting two connectors with
// different origins behind one hostname. Reclaim hints are for a spec left
// behind by a previous process, never one alive in this one.
var (
	selfCachedMu sync.Mutex
	selfCached   = map[string]bool{}
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
	_ = CacheSpec(minted)
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

// CacheDir is the directory specs are cached to and replayed from: v1.CacheDirEnv
// when set (used as-is), otherwise os.UserCacheDir() namespaced by the stable
// v1 contract package path (e.g. .../github.com/cnuss/libtunnel/v1).
func CacheDir() (string, error) {
	if d := os.Getenv(v1.CacheDirEnv); d != "" {
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

// The fixed-name hint entries tracking the most recently minted spec, written
// alongside the per-hostname files. Neither collides with cacheFileName
// output: hostnames always carry a domain.
//
// The project pair lives in the working directory (see projectDir) and is
// named to fall under the "*.local" line that the common gitignore templates
// already carry — a spec is credentials, and the one thing worse than an
// untracked credential file is a tracked one. The cache-dir pair keeps its
// original names so an existing deployment's hint still reads.
const (
	latestSpecFile   = "latest.spec.json"
	latestOwnerFile  = "latest.spec.owner"
	projectSpecFile  = "libtunnel.local"
	projectOwnerFile = "libtunnel.owner.local"
)

// specOwner records which process holds the tunnel a hint points at, written
// beside the hint itself. It is the cross-process half of the reclaim guard
// that selfCached provides in-process (#157).
type specOwner struct {
	PID      int    `json:"pid"`
	Hostname string `json:"hostname"`
}

// projectDir reports the working directory to scope hints to, and whether
// project scoping applies at all. It does not when v1.CacheDirEnv is set: an
// explicit cache dir is a deliberate statement about where specs live (a CI
// cache, a container mount), and nothing should then be written into the
// working tree. "Most recent" is otherwise a machine-global fact, which is
// the wrong scope — what a person means by it is almost always this project,
// and two projects worked on the same afternoon should not fight over one
// hint (#158).
func projectDir() (string, bool) {
	if os.Getenv(v1.CacheDirEnv) != "" {
		return "", false
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	return cwd, true
}

// writeHint writes a hint file and its owner sidecar into dir. Mode 0600 on
// both: a spec is credentials.
func writeHint(dir, specFile, ownerFile string, data []byte, host string) error {
	if err := os.WriteFile(filepath.Join(dir, specFile), data, 0o600); err != nil {
		return err
	}
	owner, err := json.Marshal(specOwner{PID: os.Getpid(), Hostname: host})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ownerFile), owner, 0o600)
}

// loadHint reads one hint pair into spec, reporting whether it may be offered
// as a reclaim hint. Every failure — no file, malformed envelope, foreign
// backend — reads as absent, as does a spec whose tunnel is still connected:
// this process's own (selfCached) or another live process's (the owner
// sidecar).
func loadHint[T v1.Spec](dir, specFile, ownerFile, backend string, spec T) bool {
	data, err := os.ReadFile(filepath.Join(dir, specFile))
	if err != nil {
		return false
	}
	tag, raw, err := DecodeSpec(string(data))
	if err != nil || tag != backend {
		return false
	}
	if json.Unmarshal(raw, spec) != nil {
		return false
	}
	host := spec.GetHostname()
	selfCachedMu.Lock()
	self := selfCached[host]
	selfCachedMu.Unlock()
	if self {
		return false
	}
	return !ownedByLiveProcess(filepath.Join(dir, ownerFile), host)
}

// ownedByLiveProcess reports whether the owner sidecar at path names a
// running process still holding host. A hint whose owner is alive points at a
// LIVE tunnel: handing it out would put two connectors with different origins
// behind one hostname, which is exactly what the in-process selfCached guard
// prevents and could not see across processes (#157). No sidecar, an
// unreadable or stale one, or one naming a different hostname reads as
// unowned — the guard only ever withholds a hint on positive evidence, so its
// worst case is a fresh mint rather than a collision.
func ownedByLiveProcess(path, host string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var owner specOwner
	if json.Unmarshal(data, &owner) != nil || owner.Hostname != host {
		return false
	}
	return pidAlive(owner.PID)
}

// pidAlive reports whether pid is a running process. Signal 0 is the standard
// POSIX liveness probe (permission denied means it exists but belongs to
// someone else); on Windows os.FindProcess itself fails for a process that is
// gone. Pid reuse makes this a heuristic, but one that fails safe: a reused
// pid withholds a reclaimable hint and costs a fresh mint, never a collision.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

// CacheSpec writes a freshly minted spec to CacheDir as <hostname>.spec.json
// (Serialize output, the v1.SpecEnv envelope) and as latest.spec.json, the
// fixed-name entry LatestSpec reads. Best effort: callers ignore the error —
// the cache is a convenience, not the source of truth. Only minted specs are
// cached (see envProvider.Spec, and the e2e preflight's direct mint); adopted
// or From-loaded specs are not re-written.
func CacheSpec[T v1.Spec](spec T) error {
	host := spec.GetHostname()
	if host == "" {
		return nil // nothing to key the file on
	}
	// Recorded before the write (and regardless of its outcome): this
	// process now owns that tunnel, so its own LatestSpec must never hand
	// the spec back out as a reclaim hint (see selfCached).
	selfCachedMu.Lock()
	selfCached[host] = true
	selfCachedMu.Unlock()
	dir, err := CacheDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data := []byte(spec.Serialize())
	if err := os.WriteFile(filepath.Join(dir, cacheFileName(host)), data, 0o600); err != nil {
		return err
	}
	// Write-through: the project hint is where this project's identity lives,
	// the cache-dir one keeps the existing machine-wide behaviour intact.
	// Best effort on the project side — a read-only working directory (a
	// container mount, / as the cwd) degrades to the cache dir rather than
	// failing the mint.
	if cwd, ok := projectDir(); ok {
		_ = writeHint(cwd, projectSpecFile, projectOwnerFile, data, host)
	}
	return writeHint(dir, latestSpecFile, latestOwnerFile, data, host)
}

// LatestSpec loads the most recently minted spec (CacheDir's
// latest.spec.json) into the caller-allocated spec, reporting whether one was
// loaded. It feeds backend-driven reclamation (#142): the fields seed the
// mint request's reclaim hints and the backend decides whether to hand the
// tunnel back — never adopt it as credentials. Accordingly every failure —
// no file, unreadable cache dir, malformed envelope, foreign backend — reads
// as absent rather than an error, and so does a spec this process cached
// itself (its tunnel is alive right here — see selfCached).
func LatestSpec[T v1.Spec](backend string, spec T) bool {
	// The project's own hint decides when it exists: falling back to the
	// machine-wide one would reintroduce the cross-project bleed the project
	// scope exists to stop.
	if cwd, ok := projectDir(); ok {
		if _, err := os.Stat(filepath.Join(cwd, projectSpecFile)); err == nil {
			return loadHint(cwd, projectSpecFile, projectOwnerFile, backend, spec)
		}
	}
	dir, err := CacheDir()
	if err != nil {
		return false
	}
	return loadHint(dir, latestSpecFile, latestOwnerFile, backend, spec)
}

// cacheFileName builds a filesystem-safe "<hostname>.spec.json": GetHostname
// may carry a :port, and the colon (plus any separators) is illegal in a
// filename on some platforms.
func cacheFileName(hostname string) string {
	safe := strings.NewReplacer("/", "_", `\`, "_", ":", "_").Replace(hostname)
	return safe + ".spec.json"
}
