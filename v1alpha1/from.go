package v1alpha1

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	v1 "github.com/cnuss/libtunnel/v1"
)

// From loads a serialized spec and replays it into a tunnel. spec is resolved,
// in order: an existing file at the given path; a file in CacheDir named spec;
// a file in CacheDir named <cacheFileName(spec)> (so a bare hostname replays
// from cache); otherwise the literal JSON. It decodes the envelope and hands
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

// loadSpec turns the From argument into the serialized envelope: an existing
// file (as given, then under CacheDir by name and by cache filename), else the
// argument verbatim (a literal JSON envelope).
func loadSpec(spec string) string {
	if data, err := os.ReadFile(spec); err == nil {
		return string(data)
	}
	if dir, err := CacheDir(); err == nil {
		for _, name := range []string{spec, cacheFileName(spec)} {
			if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
				return string(data)
			}
		}
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

// Hosts lists the cached specs as public URL strings —
// "https://<hostname>:<port>/", the port backfilled to 443 when the hostname
// carries none — sorted. It reads the envelopes' hostname field, so it needs no
// backend knowledge. Best effort: a missing CacheDir or any unreadable /
// unparseable / hostname-less file is skipped, yielding a shorter (or empty)
// list rather than an error.
func Hosts() []string {
	dir, err := CacheDir()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var hosts []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".spec.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var env specEnvelope
		if err := json.Unmarshal(data, &env); err != nil || env.Hostname == "" {
			continue
		}
		hosts = append(hosts, hostURL(env.Hostname))
	}
	slices.Sort(hosts)
	return hosts
}

// hostURL renders hostname as https://<host>:<port>/, backfilling :443 when the
// hostname has no port.
func hostURL(hostname string) string {
	host := hostname
	if _, _, err := net.SplitHostPort(hostname); err != nil {
		host = net.JoinHostPort(hostname, "443")
	}
	u := url.URL{Scheme: "https", Host: host, Path: "/"}
	return u.String()
}
