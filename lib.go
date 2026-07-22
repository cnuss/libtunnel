// Package libtunnel exposes a local origin to the public internet through a
// tunnel backend (Cloudflare quick tunnels first), behind a thin, stable
// façade over stable/alpha versioned packages.
//
// The package is split into these pieces:
//
//   - libtunnel (this package) — thin façade exposing New and the backend
//     constructors. Stable surface for application code.
//   - github.com/cnuss/libtunnel/v1 — the stable Tunnel/Provider/Backend
//     interfaces and spec types. Application code that wants to declare
//     types against the contract imports this.
//   - github.com/cnuss/libtunnel/v1alpha1 — the current implementation: the
//     lazy tunnel core plus generic providers, with backend engines in
//     subpackages (v1alpha1/cloudflare). Internals may change between alpha
//     revisions.
//
// Everything is lazy: New returns immediately, and the edge connection starts
// on first demand — WithListener provides the origin listener explicitly,
// WithLocalURL points at an already-running local origin instead (the
// cloudflared `tunnel --url` shape), and Listener, URL, and TunnelReady mint
// a loopback listener if no origin was provided.
//
//	l, _ := net.Listen("tcp", "127.0.0.1:0")
//	conn := libtunnel.New(libtunnel.Cloudflare()).WithListener(l)
//	go server.Serve(conn.Listener())
//	select {
//	case <-conn.TunnelReady():
//		fmt.Println(conn.URL()) // public https://<hostname>/
//	case <-conn.Done():
//		log.Fatal(conn.Err()) // TunnelReady never closes on failure
//	}
package libtunnel

import (
	"encoding/json"
	"fmt"
	"runtime/debug"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// modulePath is libtunnel's import path — used to find libtunnel's own entry
// in an importer's build info.
const modulePath = "github.com/cnuss/libtunnel"

// version is stamped into libtunnel's own release binaries via
// -ldflags "-X github.com/cnuss/libtunnel.version=<tag>" (the Makefile,
// Dockerfile, and release workflow all pass the release tag). It is empty in
// a plain `go build` and in every downstream consumer's build, where Version
// derives the value from build info instead.
var version string

// Version reports the libtunnel release this build links against — e.g.
// "v0.0.29". It matches the git tag and the published container image tag, so
// a consumer can pin the image to the exact library version it compiles
// against:
//
//	image := "ghcr.io/cnuss/libtunnel:" + libtunnel.Version()
//
// Resolution, in order: the release stamp (set only in libtunnel's own
// release binaries); the module version recorded in the importer's build info
// (the common consumer case — the version required in their go.mod); the
// main-module version; and finally the short VCS revision of a local build
// (with a -dirty suffix for an uncommitted tree). A build carrying no version
// information at all returns "unknown".
//
// Image tag convention: each release publishes ghcr.io/cnuss/libtunnel tagged
// with both the v-prefixed release tag (matching Version exactly) and the
// bare semver ("0.0.29", "0.0"), plus "latest" — so concatenating Version
// onto the image name resolves to the matching image with no trimming.
func Version() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	// Consumer build: libtunnel is a dependency — return the module version
	// the importer pinned (following a replace directive if one redirects it).
	for _, dep := range info.Deps {
		if dep.Path != modulePath {
			continue
		}
		if dep.Replace != nil {
			dep = dep.Replace
		}
		if dep.Version != "" {
			return dep.Version
		}
	}
	// libtunnel is the main module (its own binary, or its tests): the main
	// module version, then the VCS stamp.
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return vcsVersion(info)
}

// vcsVersion is the local-build fallback: the short VCS revision with a
// -dirty suffix for an uncommitted tree, or "unknown" when the build carries
// no VCS stamp.
func vcsVersion(info *debug.BuildInfo) string {
	var revision, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if revision == "" {
		return "unknown"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	return revision + dirty
}

// TunnelV1 is the tunnel handle returned by New: a non-generic alias for
// v1.Tunnel, re-exported so callers can name the type without importing v1.
// Storable as a plain field — the backend spec type does not appear in it.
type TunnelV1 = v1.Tunnel

// CloudflareV1 is the Cloudflare backend's contract type: an alias for
// v1.Backend[*cloudflare.Spec], re-exported so callers can declare fields and
// parameters without importing v1 or the cloudflare package. Cloudflare()
// returns the concrete *cloudflare.Backend (which satisfies this), so the
// backend-specific setters (WithID and friends) stay reachable.
type CloudflareV1 = v1.Backend[*cloudflare.Spec]

// New returns an unstarted tunnel on the given backend, which also supplies
// the credential chain. T is the backend's spec type, inferred from the
// backend and used only to wire the credential chain — it does not appear in
// the returned type, so the tunnel reference is non-generic and storable
// without threading the spec type through caller code:
//
//	libtunnel.New(libtunnel.Cloudflare())
//
// Configure the result with With* methods; WithListener starts the
// connection.
func New[T v1.Spec](backend v1.Backend[T]) TunnelV1 {
	return v1alpha1.New(backend)
}

// Cloudflare returns the Cloudflare backend: an in-process cloudflared
// quick-tunnel engine (no cloudflared binary required). Its credential chain
// resolves env first: adopt a spec from the LIBTUNNEL_SPEC environment
// variable when a parent process handed one off, replay the spec
// LIBTUNNEL_FROM references (hostname, file path, or literal JSON — From's
// resolution), and mint an anonymous *.trycloudflare.com quick tunnel
// otherwise. A resolved spec is exported back into the environment so
// spawned children inherit the same tunnel identity; a spec this process
// exported itself is never re-adopted — a second in-process tunnel mints its
// own identity.
//
// Individual spec fields can be overridden with the backend's setters —
// WithID, WithName, WithHostname, WithAccountTag, WithSecret — or their
// LIBTUNNEL__CLOUDFLARE_* environment mirrors (env beats code, field by
// field); a complete credential set skips resolution entirely. WithApiURL
// (LIBTUNNEL__CLOUDFLARE_API_URL) points the mint at a different quick-tunnel
// endpoint. Chain the backend-specific setters before WithTLS / WithHTTP2,
// which return the CloudflareV1 interface.
func Cloudflare() *cloudflare.Backend {
	return cloudflare.New()
}

// From returns an unstarted tunnel that replays a previously serialized spec
// instead of minting or adopting one — the credentials are pinned, so it
// connects under the same hostname. spec is resolved in order: an existing file
// at that path; a file of that name in the cache dir; a cached spec for that
// hostname (so From("foo.trycloudflare.com") replays the cached mint); finally
// the serialized JSON itself. The cache dir is LIBTUNNEL_CACHE_DIR when set,
// else a per-user location under os.UserCacheDir() — where a mint writes its
// spec.
//
// Like New, it returns immediately and WithListener (or Listener) starts the
// connection. A spec that can't be parsed, or whose backend tag is unknown,
// yields a tunnel already canceled with that cause — surfaced through
// Err()/Done(), per the façade's no-error contract.
//
// The LIBTUNNEL_FROM environment variable is From's operator-side mirror: it
// takes the same spec reference and replays it through any backend's
// credential chain — including over a code-pinned From spec, after
// LIBTUNNEL_SPEC (env beats code; SPEC beats FROM).
func From(spec string) TunnelV1 {
	return v1alpha1.From(spec, func(backend string, raw json.RawMessage) (v1.Tunnel, error) {
		switch backend {
		case "cloudflare":
			s := &cloudflare.Spec{}
			if err := json.Unmarshal(raw, s); err != nil {
				return nil, fmt.Errorf("invalid cloudflare spec: %w", err)
			}
			return v1alpha1.New(cloudflare.From(s)), nil
		default:
			return nil, fmt.Errorf("unknown backend %q", backend)
		}
	})
}

// Hosts lists the public URLs of the specs cached on disk —
// "https://<hostname>:443/" each, sorted — from LIBTUNNEL_CACHE_DIR if set,
// else a per-user location under os.UserCacheDir(). A mint caches its spec
// there, so this enumerates the tunnels From can replay. Best effort: an
// unreadable cache yields a shorter or empty list, never an error.
func Hosts() []string {
	return v1alpha1.Hosts()
}

// CacheDir is where minted specs are cached and where From and Hosts look:
// LIBTUNNEL_CACHE_DIR if set, else a per-user location under os.UserCacheDir().
// Empty if no per-user cache directory can be determined.
func CacheDir() string {
	dir, err := v1alpha1.CacheDir()
	if err != nil {
		return ""
	}
	return dir
}
