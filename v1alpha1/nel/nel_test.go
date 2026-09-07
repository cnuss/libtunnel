package nel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"
)

// harness is a TLS origin that sets NEL + Report-To pointing at an in-process
// collector, and a transport whose deliveries are captured rather than
// posted. Reports are fed back synchronously through deliver so a test reads
// them without racing the background send.
type harness struct {
	origin    *httptest.Server
	collector string
	tr        *transport
	status    int
	nel       string
	reportTo  string
	got       chan delivery
}

type delivery struct {
	endpoint string
	reports  []report
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{status: http.StatusOK, collector: "http://127.0.0.1:9/collect", got: make(chan delivery, 16)}
	h.origin = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.nel != "" {
			w.Header().Set("NEL", h.nel)
		}
		if h.reportTo != "" {
			w.Header().Set("Report-To", h.reportTo)
		}
		w.WriteHeader(h.status)
	}))
	t.Cleanup(h.origin.Close)
	h.reportTo = fmt.Sprintf(`{"group":"g","max_age":600,"endpoints":[{"url":%q}]}`, h.collector)
	h.nel = `{"report_to":"g","max_age":600}`

	base := h.origin.Client().Transport
	h.tr = &transport{
		base:      base,
		userAgent: "libtunnel/test",
		store:     &cache{policies: map[string]policy{}, groups: map[string]map[string]group{}},
	}
	h.tr.log = discard()
	h.tr.deliver = func(_ context.Context, ep string, body []byte) error {
		var rs []report
		if err := json.Unmarshal(body, &rs); err != nil {
			t.Errorf("report body is not a JSON array of reports: %v", err)
			return err
		}
		h.got <- delivery{endpoint: ep, reports: rs}
		return nil
	}
	return h
}

func (h *harness) do(t *testing.T) (*http.Response, error) {
	t.Helper()
	client := &http.Client{Transport: h.tr}
	return client.Get(h.origin.URL + "/tunnel")
}

func (h *harness) expectReport(t *testing.T) delivery {
	t.Helper()
	select {
	case d := <-h.got:
		return d
	case <-time.After(2 * time.Second):
		t.Fatal("no report delivered")
		return delivery{}
	}
}

func (h *harness) expectNoReport(t *testing.T) {
	t.Helper()
	select {
	case d := <-h.got:
		t.Fatalf("unexpected report: %+v", d.reports)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestPolicyAppliesToLaterRequestsOnly pins the spec's order: the response
// that carries a policy is not reported under it. A browser has the same
// blind spot, and matching it is what keeps this a NEL client rather than a
// telemetry client wearing NEL's headers.
func TestPolicyAppliesToLaterRequestsOnly(t *testing.T) {
	h := newHarness(t)
	h.status = http.StatusTooManyRequests

	h.do(t)
	h.expectNoReport(t)

	h.do(t)
	d := h.expectReport(t)
	if d.endpoint != h.collector {
		t.Errorf("delivered to %q, want the collector %q", d.endpoint, h.collector)
	}
	if len(d.reports) != 1 {
		t.Fatalf("delivered %d reports, want 1", len(d.reports))
	}
	r := d.reports[0]
	if r.Type != "network-error" {
		t.Errorf("type = %q, want network-error", r.Type)
	}
	if r.UserAgent != "libtunnel/test" {
		t.Errorf("user_agent = %q", r.UserAgent)
	}
	if r.URL != h.origin.URL+"/tunnel" {
		t.Errorf("url = %q, want %q", r.URL, h.origin.URL+"/tunnel")
	}
	b := r.Body
	if b.Type != "http.error" || b.Phase != "application" || b.StatusCode != 429 {
		t.Errorf("body = type %q phase %q status %d, want http.error/application/429", b.Type, b.Phase, b.StatusCode)
	}
	if b.Method != http.MethodGet {
		t.Errorf("method = %q", b.Method)
	}
	if b.SamplingFraction != 1 {
		t.Errorf("sampling_fraction = %v, want the failure default of 1", b.SamplingFraction)
	}
	if b.ServerIP != "127.0.0.1" {
		t.Errorf("server_ip = %q", b.ServerIP)
	}
	if b.Protocol == "" {
		t.Error("protocol is empty")
	}
}

// TestSuccessIsSampledByItsOwnFraction pins that success_fraction governs ok
// reports independently of failure_fraction: Cloudflare sets it to 0, so a
// healthy mint is never reported, and 1 reports every one.
func TestSuccessIsSampledByItsOwnFraction(t *testing.T) {
	h := newHarness(t)
	h.nel = `{"report_to":"g","max_age":600,"success_fraction":0}`
	h.do(t)
	h.do(t)
	h.expectNoReport(t)

	h.nel = `{"report_to":"g","max_age":600,"success_fraction":1}`
	h.do(t) // learns the new fraction
	h.do(t)
	d := h.expectReport(t)
	if b := d.reports[0].Body; b.Type != "ok" || b.StatusCode != 200 {
		t.Errorf("body = type %q status %d, want ok/200", b.Type, b.StatusCode)
	}
}

// TestMaxAgeZeroForgetsThePolicy pins the spec's removal signal.
func TestMaxAgeZeroForgetsThePolicy(t *testing.T) {
	h := newHarness(t)
	h.status = http.StatusTooManyRequests
	h.do(t)

	h.nel = `{"max_age":0}`
	h.do(t) // reported under the old policy, then forgets it
	h.expectReport(t)

	h.do(t)
	h.expectNoReport(t)
}

// TestDeniedHeadersNeverAppear pins the floor under a policy's allowlist: a
// server asking for a credential does not get it, no matter what it names.
func TestDeniedHeadersNeverAppear(t *testing.T) {
	h := newHarness(t)
	h.status = http.StatusTooManyRequests
	h.nel = `{"report_to":"g","max_age":600,"request_headers":["Authorization","X-Record-Id","X-Client"],"response_headers":["Set-Cookie","Retry-After"]}`
	h.do(t)

	client := &http.Client{Transport: h.tr}
	req, _ := http.NewRequest(http.MethodGet, h.origin.URL+"/tunnel", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("X-Record-Id", "rec_secret")
	req.Header.Set("X-Client", "yes")
	client.Do(req)

	d := h.expectReport(t)
	b := d.reports[0].Body
	for _, name := range []string{"Authorization", "X-Record-Id"} {
		if _, ok := b.RequestHeaders[name]; ok {
			t.Errorf("request header %s was reported", name)
		}
	}
	if b.RequestHeaders["X-Client"] != "yes" {
		t.Errorf("allowed header missing: %v", b.RequestHeaders)
	}
	if _, ok := b.ResponseHeaders["Set-Cookie"]; ok {
		t.Error("Set-Cookie was reported")
	}
	raw, _ := json.Marshal(d.reports)
	if strings.Contains(string(raw), "secret") {
		t.Errorf("a credential leaked into the report: %s", raw)
	}
}

// TestTwoGroupsInOneHeader pins the Report-To value's shape: JSON objects,
// comma-separated, no enclosing array — and that a NEL policy naming one of
// them reports to that one.
func TestTwoGroupsInOneHeader(t *testing.T) {
	h := newHarness(t)
	h.status = http.StatusTooManyRequests
	h.reportTo = `{"group":"cf-nel","max_age":600,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v4?s=x"}]}, ` +
		fmt.Sprintf(`{"group":"g","max_age":600,"endpoints":[{"url":%q}]}`, h.collector)
	h.do(t)
	h.do(t)
	d := h.expectReport(t)
	if d.endpoint != h.collector {
		t.Errorf("delivered to %q, want group g's collector", d.endpoint)
	}
}

// TestEndpointSelection pins the spec's SRV-shaped choice: lowest priority
// wins outright; ties split by weight.
func TestEndpointSelection(t *testing.T) {
	c := &cache{policies: map[string]policy{}, groups: map[string]map[string]group{}}
	now := time.Now()
	c.learn("https://o", headers("Report-To",
		`{"group":"g","max_age":600,"endpoints":[`+
			`{"url":"https://low","priority":2},`+
			`{"url":"https://a","priority":1,"weight":0},`+
			`{"url":"https://b","priority":1,"weight":10}]}`,
	), now)
	seen := map[string]int{}
	for range 50 {
		ep, ok := c.endpoint("https://o", "g", now)
		if !ok {
			t.Fatal("no endpoint")
		}
		seen[ep]++
	}
	if seen["https://low"] != 0 {
		t.Errorf("a priority-2 endpoint was chosen over priority-1: %v", seen)
	}
	if seen["https://a"] != 0 {
		t.Errorf("a weight-0 endpoint was chosen: %v", seen)
	}
	if seen["https://b"] != 50 {
		t.Errorf("want all 50 picks on b: %v", seen)
	}
}

// TestUntrustworthyEndpointsAreDropped pins the Reporting API's bar: https,
// or loopback. A plain-http collector on a public host gets nothing.
func TestUntrustworthyEndpointsAreDropped(t *testing.T) {
	c := &cache{policies: map[string]policy{}, groups: map[string]map[string]group{}}
	now := time.Now()
	c.learn("https://o", headers(
		"Report-To", `{"group":"g","max_age":600,"endpoints":[{"url":"http://collector.example/"}]}`,
		"NEL", `{"report_to":"g","max_age":600}`,
	), now)
	if _, ok := c.policy("https://o", now); !ok {
		t.Fatal("the policy itself was not learned")
	}
	if _, ok := c.endpoint("https://o", "g", now); ok {
		t.Error("an http endpoint on a public host was accepted")
	}
	for _, u := range []string{"http://localhost/c", "http://127.0.0.1:9/c", "http://[::1]/c", "https://x/c"} {
		if !trustworthy(u) {
			t.Errorf("%s should be trustworthy", u)
		}
	}
}

// TestPlainHTTPResponsesTeachNothing pins that a policy only comes over TLS,
// per the spec's secure-context requirement.
func TestPlainHTTPResponsesTeachNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("NEL", `{"report_to":"g","max_age":600}`)
		w.Header().Set("Report-To", `{"group":"g","max_age":600,"endpoints":[{"url":"http://127.0.0.1:9/c"}]}`)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	got := make(chan delivery, 1)
	tr := &transport{base: http.DefaultTransport, log: discard(),
		store:   &cache{policies: map[string]policy{}, groups: map[string]map[string]group{}},
		deliver: func(_ context.Context, ep string, _ []byte) error { got <- delivery{endpoint: ep}; return nil }}
	client := &http.Client{Transport: tr}
	client.Get(srv.URL)
	client.Get(srv.URL)
	select {
	case d := <-got:
		t.Fatalf("a policy was learned over plain http and reported to %q", d.endpoint)
	case <-time.After(100 * time.Millisecond):
	}
}

// TestOptOutIsAPassthrough pins the switch: with the env set, Transport hands
// back the base and nothing is cached or sent.
func TestOptOutIsAPassthrough(t *testing.T) {
	t.Setenv(OptOutEnv, "1")
	base := http.DefaultTransport
	if got := Transport(base, "ua", nil); got != base {
		t.Errorf("Transport returned %T, want the base back", got)
	}
}

// TestErrorClassification pins the map from Go's errors onto the spec's
// types, by phase.
func TestErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		connected bool
		dnsDone   bool
		phase     string
		typ       string
	}{
		{"nxdomain", &net.DNSError{IsNotFound: true}, false, false, "dns", "dns.name_not_resolved"},
		{"dns timeout", &net.DNSError{IsTimeout: true}, false, false, "dns", "dns.unreachable"},
		{"dns other", &net.DNSError{}, false, false, "dns", "dns.failed"},
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, false, true, "connection", "tcp.refused"},
		{"reset", &net.OpError{Op: "dial", Err: syscall.ECONNRESET}, false, true, "connection", "tcp.reset"},
		{"unreachable", &net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}, false, true, "connection", "tcp.address_unreachable"},
		{"dial timeout", context.DeadlineExceeded, false, true, "connection", "tcp.timed_out"},
		{"dial canceled", context.Canceled, false, true, "connection", "tcp.aborted"},
		{"dial unknown", errors.New("x"), false, true, "connection", "tcp.failed"},
		{"before dns", errors.New("x"), false, false, "dns", "dns.failed"},
		{"unknown authority", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, false, true, "connection", "tls.cert.authority_invalid"},
		{"name mismatch", x509.HostnameError{Host: "x"}, false, true, "connection", "tls.cert.name_invalid"},
		{"expired", x509.CertificateInvalidError{Reason: x509.Expired}, false, true, "connection", "tls.cert.date_invalid"},
		{"cert invalid", x509.CertificateInvalidError{Reason: x509.CANotAuthorizedForThisName}, false, true, "connection", "tls.cert.invalid"},
		{"tls alert", tls.AlertError(40), false, true, "connection", "tls.protocol.error"},
		{"app canceled", context.Canceled, true, true, "application", "abandoned"},
		{"app timeout", context.DeadlineExceeded, true, true, "application", "abandoned"},
		{"app reset", syscall.ECONNRESET, true, true, "application", "http.response.invalid"},
		{"app other", errors.New("x"), true, true, "application", "http.failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			phase, typ := classifyError(tc.err, tc.connected, tc.dnsDone)
			if phase != tc.phase || typ != tc.typ {
				t.Errorf("got %s/%s, want %s/%s", phase, typ, tc.phase, tc.typ)
			}
		})
	}
}

// TestDNSPhaseStripsConnectionFields pins the spec's shape for a DNS-phase
// report: nothing was reached, so server_ip, protocol and elapsed_time are
// absent rather than misleading.
func TestDNSPhaseStripsConnectionFields(t *testing.T) {
	got := make(chan delivery, 1)
	c := &cache{policies: map[string]policy{}, groups: map[string]map[string]group{}}
	c.learn("https://no-such-host.invalid", headers(
		"Report-To", `{"group":"g","max_age":600,"endpoints":[{"url":"http://127.0.0.1:9/c"}]}`,
		"NEL", `{"report_to":"g","max_age":600}`,
	), time.Now())
	tr := &transport{base: http.DefaultTransport, log: discard(), store: c,
		deliver: func(_ context.Context, ep string, body []byte) error {
			var rs []report
			json.Unmarshal(body, &rs)
			got <- delivery{endpoint: ep, reports: rs}
			return nil
		}}
	(&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://no-such-host.invalid/x")
	select {
	case d := <-got:
		b := d.reports[0].Body
		if b.Phase != "dns" {
			t.Fatalf("phase = %q, want dns (type %q)", b.Phase, b.Type)
		}
		if b.ServerIP != "" || b.Protocol != "" || b.ElapsedTime != 0 {
			t.Errorf("dns-phase report carries server_ip %q protocol %q elapsed %d", b.ServerIP, b.Protocol, b.ElapsedTime)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no report for an unresolvable host")
	}
}

// TestEnvelopeStripsCredentialsFromURL pins the spec's serialization: no
// userinfo, no fragment.
func TestEnvelopeStripsCredentialsFromURL(t *testing.T) {
	u, _ := url.Parse("https://user:pw@host/path?q=1#frag")
	if got, want := stripped(u), "https://host/path?q=1"; got != want {
		t.Errorf("stripped = %q, want %q", got, want)
	}
}

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// headers builds an http.Header through Set, which canonicalizes names the
// way a real response's parser does — NEL arrives as Nel. A map literal keyed
// "NEL" is a header no lookup ever finds.
func headers(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}
