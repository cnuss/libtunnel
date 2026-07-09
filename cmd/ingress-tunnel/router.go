package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"

	netv1 "k8s.io/api/networking/v1"
)

// buildHandler compiles an Ingress's rules into an http.Handler that
// reverse-proxies each path to its backing Service. Paths are matched
// longest-first so the most specific prefix wins; PathType Exact requires an
// exact match, Prefix/ImplementationSpecific match on segment boundaries.
//
// Host rules are honored when the request Host matches, but quick-tunnel
// traffic always arrives under the random *.trycloudflare.com host, so
// host-scoped rules rarely fire in practice — path routing is the real path.
// Returns nil when the Ingress has no usable (Service + numeric port) backend.
func buildHandler(ing *netv1.Ingress) http.Handler {
	type route struct {
		host  string
		path  string
		exact bool
		proxy http.Handler
	}
	var routes []route
	add := func(host string, p netv1.HTTPIngressPath) {
		u := backendURL(ing.Namespace, p.Backend)
		if u == nil {
			return
		}
		routes = append(routes, route{
			host:  host,
			path:  p.Path,
			exact: p.PathType != nil && *p.PathType == netv1.PathTypeExact,
			proxy: newProxy(u),
		})
	}
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			add(r.Host, p)
		}
	}

	var defaultProxy http.Handler
	if db := ing.Spec.DefaultBackend; db != nil {
		if u := backendURL(ing.Namespace, *db); u != nil {
			defaultProxy = newProxy(u)
		}
	}
	if len(routes) == 0 && defaultProxy == nil {
		return nil
	}
	sort.SliceStable(routes, func(i, j int) bool { return len(routes[i].path) > len(routes[j].path) })

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for _, rt := range routes {
			if rt.host != "" && !strings.EqualFold(rt.host, hostOnly(req.Host)) {
				continue
			}
			if rt.exact {
				if req.URL.Path == rt.path {
					rt.proxy.ServeHTTP(w, req)
					return
				}
				continue
			}
			if pathMatch(req.URL.Path, rt.path) {
				rt.proxy.ServeHTTP(w, req)
				return
			}
		}
		if defaultProxy != nil {
			defaultProxy.ServeHTTP(w, req)
			return
		}
		http.NotFound(w, req)
	})
}

// pathMatch reports whether reqPath is covered by the Prefix path p, matching
// only on segment boundaries (/foo matches /foo and /foo/bar, not /foobar).
func pathMatch(reqPath, p string) bool {
	if p == "" || p == "/" {
		return true
	}
	if reqPath == p {
		return true
	}
	return strings.HasPrefix(reqPath, strings.TrimSuffix(p, "/")+"/")
}

// hostOnly strips any :port from a request Host.
func hostOnly(h string) string {
	if i := strings.IndexByte(h, ':'); i >= 0 {
		return h[:i]
	}
	return h
}

// backendURL is the in-cluster URL for an Ingress backend Service:
// http://<name>.<namespace>.svc.cluster.local:<port>. Named ports are not
// resolved in this PoC (they need a Service lookup), so a backend without a
// numeric port yields nil and is skipped.
func backendURL(ns string, b netv1.IngressBackend) *url.URL {
	if b.Service == nil || b.Service.Port.Number == 0 {
		return nil
	}
	return &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s.%s.svc.cluster.local:%d", b.Service.Name, ns, b.Service.Port.Number),
	}
}

// newProxy is a reverse proxy to u, rewriting Host so name-based vhosts in the
// cluster see their own host rather than the public trycloudflare hostname.
func newProxy(u *url.URL) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = u.Host
		},
	}
}
