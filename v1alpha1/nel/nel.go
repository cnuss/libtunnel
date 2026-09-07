// Package nel reports network errors to a server the way a browser does.
//
// A server that wants to hear about the failures its clients see sets two
// response headers: NEL names a reporting group and a sampling policy, and
// Report-To maps that group to collector endpoints. A browser caches the
// policy per origin and, for later requests to that origin, posts a
// network-error report to the collector — a 4xx, a timeout, a name that did
// not resolve, a certificate it would not trust. This package is that client:
// a RoundTripper that does the same for an http.Client.
//
// Cloudflare sets both headers on every response from a zone with Network
// Error Logging on, which puts the reports in that zone's analytics. So a
// provider fronted by Cloudflare gets client-side failure telemetry for its
// mint endpoint without running anything.
//
// Two specs, followed where they bear on a non-browser client:
// https://www.w3.org/TR/network-error-logging/ and the Report-To draft of the
// Reporting API, https://www.w3.org/TR/2018/WD-reporting-1-20180925/.
package nel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
)

// OptOutEnv disables reporting when set to anything non-empty. Reports only
// ever go to a collector the server the caller is already talking to
// advertised, so no new party learns anything — but a library that phones
// out is still a library that phones out, and this is the switch.
const OptOutEnv = v1.NoReportEnv

// deliverTimeout bounds one report POST. One attempt, no queue, no backoff:
// the spec's retry machinery is for a long-lived browser, and a report about
// a failure must never delay or cause one.
const deliverTimeout = 5 * time.Second

// denied are headers no policy can ask for. A server naming them in
// request_headers or response_headers gets the report without them.
var denied = map[string]bool{
	"authorization": true,
	"cookie":        true,
	"set-cookie":    true,
	"x-record-id":   true,
}

// policy is one origin's cached NEL policy: where to report and how often.
type policy struct {
	group           string
	expires         time.Time
	successFraction float64
	failureFraction float64
	requestHeaders  []string
	responseHeaders []string
}

// group is one Report-To endpoint group.
type group struct {
	expires   time.Time
	endpoints []endpoint
}

type endpoint struct {
	url      string
	priority int
	weight   int
}

// cache is the per-origin policy store: what a browser keeps for as long as
// max_age says to. Process-wide, so every client in the process shares one
// view of an origin, the way every tab does.
type cache struct {
	mu       sync.Mutex
	policies map[string]policy           // by origin
	groups   map[string]map[string]group // by origin, then group name
}

var store = &cache{
	policies: map[string]policy{},
	groups:   map[string]map[string]group{},
}

// Transport wraps base so every request through it is reported per the NEL
// policy its origin has set. userAgent is what the report says sent it, in
// the user_agent field the Reporting API reserves for exactly that.
//
// With OptOutEnv set, base is returned as is.
func Transport(base http.RoundTripper, userAgent string, log *slog.Logger) http.RoundTripper {
	if os.Getenv(OptOutEnv) != "" {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &transport{base: base, userAgent: userAgent, log: log, store: store}
}

type transport struct {
	base      http.RoundTripper
	userAgent string
	log       *slog.Logger
	store     *cache
	// deliver is the POST, behind a field so a test can watch it without a
	// second server.
	deliver func(ctx context.Context, endpoint string, body []byte) error
}

// RoundTrip runs the request, decides whether it is reportable under the
// policy the origin already had, then learns whatever policy this response
// carries. That order is the spec's: a policy applies to requests after the
// one that delivered it.
func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	origin := originOf(req.URL)
	start := time.Now()

	var (
		serverIP  string
		connected bool
		dnsDone   bool
	)
	trace := &httptrace.ClientTrace{
		DNSDone: func(httptrace.DNSDoneInfo) { dnsDone = true },
		GotConn: func(info httptrace.GotConnInfo) {
			connected = true
			if addr := info.Conn.RemoteAddr(); addr != nil {
				if host, _, err := net.SplitHostPort(addr.String()); err == nil {
					serverIP = host
				}
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := t.base.RoundTrip(req)
	elapsed := time.Since(start)

	if pol, ok := t.store.policy(origin, time.Now()); ok {
		if body := classify(resp, err, pol, connected, dnsDone); body != nil {
			body.ServerIP = serverIP
			body.ElapsedTime = elapsed.Milliseconds()
			body.Method = req.Method
			body.RequestHeaders = pick(req.Header, pol.requestHeaders)
			if resp != nil {
				body.ResponseHeaders = pick(resp.Header, pol.responseHeaders)
				if resp.TLS != nil {
					body.Protocol = resp.TLS.NegotiatedProtocol
				}
				if body.Protocol == "" {
					body.Protocol = "http/1.1"
				}
			}
			if body.Phase == "dns" {
				// The spec strips these for DNS-phase errors: nothing was
				// reached, so there is no server, protocol or elapsed time to
				// speak of.
				body.ServerIP = ""
				body.Protocol = ""
				body.ElapsedTime = 0
			}
			if ep, ok := t.store.endpoint(origin, pol.group, time.Now()); ok {
				t.send(ep, report{
					Age:       0,
					Type:      "network-error",
					URL:       stripped(req.URL),
					UserAgent: t.userAgent,
					Body:      body,
				})
			}
		}
	}

	if resp != nil && req.URL.Scheme == "https" {
		t.store.learn(origin, resp.Header, time.Now())
	}
	return resp, err
}

// send delivers one report in the background, one attempt, and forgets it.
func (t *transport) send(ep string, r report) {
	body, err := json.Marshal([]report{r})
	if err != nil {
		return
	}
	deliver := t.deliver
	if deliver == nil {
		// Over the same transport the request went out on, so the report
		// verifies the collector with the same trust set — a host with no CA
		// bundle that could reach the provider can reach its collector.
		deliver = func(ctx context.Context, ep string, body []byte) error {
			return post(ctx, t.base, ep, body)
		}
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
		defer cancel()
		if err := deliver(ctx, ep, body); err != nil {
			t.log.Debug("network error report not delivered", "endpoint", ep, "error", err)
			return
		}
		t.log.Debug("network error reported", "endpoint", ep, "type", r.Body.Type, "phase", r.Body.Phase)
	}()
}

// post is the Reporting API delivery: a POST of a JSON array of reports,
// typed as such.
func post(ctx context.Context, via http.RoundTripper, ep string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/reports+json")
	resp, err := (&http.Client{Transport: via}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New(resp.Status)
	}
	return nil
}

// report is the Reporting API envelope around a NEL body.
type report struct {
	Age       int64  `json:"age"`
	Type      string `json:"type"`
	URL       string `json:"url"`
	UserAgent string `json:"user_agent"`
	Body      *body  `json:"body"`
}

// body is the NEL report body, fields and names per the spec.
type body struct {
	SamplingFraction float64           `json:"sampling_fraction"`
	Referrer         string            `json:"referrer"`
	ServerIP         string            `json:"server_ip"`
	Protocol         string            `json:"protocol"`
	Method           string            `json:"method"`
	RequestHeaders   map[string]string `json:"request_headers"`
	ResponseHeaders  map[string]string `json:"response_headers"`
	StatusCode       int               `json:"status_code"`
	ElapsedTime      int64             `json:"elapsed_time"`
	Phase            string            `json:"phase"`
	Type             string            `json:"type"`
}

// classify decides whether the outcome is reported under pol and, if so,
// with which type and phase. Nil means not reported: an outcome the sampling
// left out, or nothing to say.
func classify(resp *http.Response, err error, pol policy, connected, dnsDone bool) *body {
	b := &body{RequestHeaders: map[string]string{}, ResponseHeaders: map[string]string{}}

	switch {
	case err == nil && resp != nil:
		b.StatusCode = resp.StatusCode
		b.Phase = "application"
		if resp.StatusCode >= 400 {
			b.Type = "http.error"
			b.SamplingFraction = pol.failureFraction
		} else {
			b.Type = "ok"
			b.SamplingFraction = pol.successFraction
		}
	default:
		b.Phase, b.Type = classifyError(err, connected, dnsDone)
		b.SamplingFraction = pol.failureFraction
	}

	if b.SamplingFraction <= 0 || (b.SamplingFraction < 1 && rand.Float64() >= b.SamplingFraction) {
		return nil
	}
	return b
}

// classifyError maps a Go transport error onto the spec's error types. The
// phase is the spec's three: dns, connection, application.
func classifyError(err error, connected, dnsDone bool) (phase, typ string) {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return "dns", "dns.name_not_resolved"
		case dnsErr.IsTimeout:
			return "dns", "dns.unreachable"
		default:
			return "dns", "dns.failed"
		}
	}

	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		err = certErr.Err
	}
	var (
		unknownAuthority x509.UnknownAuthorityError
		hostnameErr      x509.HostnameError
		invalidErr       x509.CertificateInvalidError
	)
	switch {
	case errors.As(err, &unknownAuthority):
		return "connection", "tls.cert.authority_invalid"
	case errors.As(err, &hostnameErr):
		return "connection", "tls.cert.name_invalid"
	case errors.As(err, &invalidErr):
		if invalidErr.Reason == x509.Expired {
			return "connection", "tls.cert.date_invalid"
		}
		return "connection", "tls.cert.invalid"
	}
	var alert tls.AlertError
	var recordErr tls.RecordHeaderError
	if errors.As(err, &alert) || errors.As(err, &recordErr) {
		return "connection", "tls.protocol.error"
	}

	if !connected {
		switch {
		case errors.Is(err, syscall.ECONNREFUSED):
			return "connection", "tcp.refused"
		case errors.Is(err, syscall.ECONNRESET):
			return "connection", "tcp.reset"
		case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
			return "connection", "tcp.address_unreachable"
		case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
			return "connection", "tcp.timed_out"
		case errors.Is(err, context.Canceled):
			return "connection", "tcp.aborted"
		}
		if dnsDone {
			return "connection", "tcp.failed"
		}
		return "dns", "dns.failed"
	}

	switch {
	case errors.Is(err, context.Canceled):
		return "application", "abandoned"
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return "application", "abandoned"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.ErrUnexpectedEOF):
		return "application", "http.response.invalid"
	}
	return "application", "http.failed"
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// pick copies the named headers, minus the denied set, into a map the spec's
// report shape wants.
func pick(h http.Header, names []string) map[string]string {
	out := map[string]string{}
	for _, name := range names {
		if denied[strings.ToLower(name)] {
			continue
		}
		if v := h.Get(name); v != "" {
			out[name] = v
		}
	}
	return out
}

// originOf is scheme://host[:port], the key a policy is cached under.
func originOf(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// stripped is the request URL as the spec wants it in the envelope: no
// username, password or fragment.
func stripped(u *url.URL) string {
	c := *u
	c.User = nil
	c.Fragment = ""
	c.RawFragment = ""
	return c.String()
}

// policy returns origin's policy if one is cached and unexpired.
func (c *cache) policy(origin string, now time.Time) (policy, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.policies[origin]
	if !ok || !now.Before(p.expires) {
		return policy{}, false
	}
	return p, true
}

// endpoint picks where a report for origin's group goes: the lowest
// priority, then weighted random among ties — the spec's SRV-shaped choice.
func (c *cache) endpoint(origin, name string, now time.Time) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	g, ok := c.groups[origin][name]
	if !ok || !now.Before(g.expires) || len(g.endpoints) == 0 {
		return "", false
	}
	best := g.endpoints[0].priority
	for _, e := range g.endpoints[1:] {
		best = min(best, e.priority)
	}
	var tier []endpoint
	total := 0
	for _, e := range g.endpoints {
		if e.priority == best {
			tier = append(tier, e)
			total += e.weight
		}
	}
	if total == 0 {
		return tier[rand.IntN(len(tier))].url, true
	}
	pick := rand.IntN(total)
	for _, e := range tier {
		if pick < e.weight {
			return e.url, true
		}
		pick -= e.weight
	}
	return tier[len(tier)-1].url, true
}

// learn updates origin's policy and groups from a response's headers.
func (c *cache) learn(origin string, h http.Header, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, raw := range h.Values("Report-To") {
		for _, g := range parseGroups(raw, now) {
			if c.groups[origin] == nil {
				c.groups[origin] = map[string]group{}
			}
			if !now.Before(g.expires) {
				delete(c.groups[origin], g.name)
				continue
			}
			c.groups[origin][g.name] = g.group
		}
	}

	if raw := h.Get("NEL"); raw != "" {
		if p, remove, ok := parsePolicy(raw, now); ok {
			if remove {
				delete(c.policies, origin)
			} else {
				c.policies[origin] = p
			}
		}
	}
}

type namedGroup struct {
	name string
	group
}

// parseGroups reads a Report-To value: JSON objects, comma-separated, with
// no enclosing array — the header's odd shape, per its spec.
func parseGroups(raw string, now time.Time) []namedGroup {
	var objs []struct {
		Group     string `json:"group"`
		MaxAge    int64  `json:"max_age"`
		Endpoints []struct {
			URL      string `json:"url"`
			Priority *int   `json:"priority"`
			Weight   *int   `json:"weight"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte("["+raw+"]"), &objs); err != nil {
		return nil
	}
	var out []namedGroup
	for _, o := range objs {
		name := o.Group
		if name == "" {
			name = "default"
		}
		g := namedGroup{name: name, group: group{expires: now.Add(time.Duration(o.MaxAge) * time.Second)}}
		for _, e := range o.Endpoints {
			if !trustworthy(e.URL) {
				continue
			}
			ep := endpoint{url: e.URL, priority: 1, weight: 1}
			if e.Priority != nil && *e.Priority >= 0 {
				ep.priority = *e.Priority
			}
			if e.Weight != nil && *e.Weight >= 0 {
				ep.weight = *e.Weight
			}
			g.endpoints = append(g.endpoints, ep)
		}
		out = append(out, g)
	}
	return out
}

// parsePolicy reads a NEL value. remove reports a max_age of 0, which the
// spec defines as "forget this origin's policy".
func parsePolicy(raw string, now time.Time) (p policy, remove bool, ok bool) {
	var o struct {
		ReportTo        string   `json:"report_to"`
		MaxAge          *int64   `json:"max_age"`
		SuccessFraction *float64 `json:"success_fraction"`
		FailureFraction *float64 `json:"failure_fraction"`
		RequestHeaders  []string `json:"request_headers"`
		ResponseHeaders []string `json:"response_headers"`
	}
	if err := json.Unmarshal([]byte(raw), &o); err != nil || o.MaxAge == nil {
		return policy{}, false, false
	}
	if *o.MaxAge <= 0 {
		return policy{}, true, true
	}
	if o.ReportTo == "" {
		return policy{}, false, false
	}
	p = policy{
		group:           o.ReportTo,
		expires:         now.Add(time.Duration(*o.MaxAge) * time.Second),
		successFraction: 0,
		failureFraction: 1,
		requestHeaders:  o.RequestHeaders,
		responseHeaders: o.ResponseHeaders,
	}
	if o.SuccessFraction != nil {
		p.successFraction = clamp(*o.SuccessFraction)
	}
	if o.FailureFraction != nil {
		p.failureFraction = clamp(*o.FailureFraction)
	}
	return p, false, true
}

func clamp(f float64) float64 { return max(0, min(1, f)) }

// trustworthy is the Reporting API's bar for an endpoint: https, or a
// loopback address, which the spec treats as secure.
func trustworthy(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
