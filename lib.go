// Package libtunnel exposes a local listener to the public internet through a
// tunnel backend (Cloudflare quick tunnels first), behind a thin, stable
// façade over stable/alpha versioned packages.
//
// The package is split into these pieces:
//
//   - libtunnel (this package) — thin façade exposing New and the backend
//     constructors. Stable surface for application code.
//   - github.com/cnuss/libtunnel/v1 — the stable Tunnel/Tunneled/Provider/
//     Backend interfaces and spec types. Application code that wants to
//     declare types against the contract imports this.
//   - github.com/cnuss/libtunnel/v1alpha1 — the current implementation: the
//     lazy tunnel core plus generic providers, with backend engines in
//     subpackages (v1alpha1/cloudflare). Internals may change between alpha
//     revisions.
//
// Everything is lazy: New returns immediately, and WithListener is the
// trigger that starts the edge connection.
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

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// TunnelV1 is the configurable phase returned by New: a non-generic alias for
// v1.Tunnel, re-exported so callers can name the type without importing v1.
// Mutators (With*) chain until WithListener narrows it to TunneledV1.
type TunnelV1 = v1.Tunnel

// TunneledV1 is the post-WithListener phase: a non-generic alias for
// v1.Tunneled (observers and lifecycle, no mutators). Storable as a plain
// field — the backend spec type does not appear in it.
type TunneledV1 = v1.Tunneled

// CloudflareV1 is the backend type returned by Cloudflare: an alias for
// v1.Backend[*cloudflare.Spec], re-exported so callers can name it without
// importing v1 or the cloudflare package.
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
// adopts a spec from the LIBTUNNEL_SPEC environment variable when a parent
// process handed one off, mints an anonymous *.trycloudflare.com quick
// tunnel otherwise, and exports a freshly minted spec back into the
// environment so spawned children inherit the same tunnel identity. A spec
// this process exported itself is never re-adopted: a second in-process
// tunnel mints its own identity.
func Cloudflare() CloudflareV1 {
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
func From(spec string) TunnelV1 {
	return v1alpha1.From(spec, func(backend string, raw json.RawMessage) (v1.Tunnel, error) {
		switch backend {
		case "cloudflare":
			s := &cloudflare.Spec{}
			if err := json.Unmarshal(raw, s); err != nil {
				return nil, fmt.Errorf("invalid cloudflare spec: %w", err)
			}
			return v1alpha1.New(cloudflare.FromSpec(s)), nil
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
