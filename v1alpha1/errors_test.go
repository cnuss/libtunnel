package v1alpha1_test

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// TestClassifyUntrustedCertificate drives a real TLS handshake against a
// server no trust store knows — the failure #162 was reported for, from a
// container shipping no CA bundle.
func TestClassifyUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	// http.DefaultClient deliberately, not srv.Client(): the missing trust is
	// the point of the test.
	resp, err := http.Post(srv.URL, "application/json", nil)
	if err == nil {
		resp.Body.Close()
		t.Fatal("request succeeded against an untrusted certificate")
	}
	if got := v1alpha1.Classify(err); got != v1.ErrCertificate {
		t.Errorf("Classify(%v) = %v, want ErrCertificate", err, got)
	}
	if v1.Budget(v1alpha1.Classify(err)) != 0 {
		t.Error("a certificate failure has a non-zero budget; it would be retried")
	}
}

// TestClassifyNXDOMAIN uses the reserved .invalid TLD (RFC 2606), which no
// resolver will ever answer. A name that does not exist is configuration, so
// it lands in ErrRejected rather than being retried.
func TestClassifyNXDOMAIN(t *testing.T) {
	resp, err := http.Get("http://libtunnel-does-not-exist.invalid/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("request to a .invalid host succeeded")
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Skipf("resolver did not return NXDOMAIN (captive portal or wildcard DNS): %v", err)
	}
	if got := v1alpha1.Classify(err); got != v1.ErrRejected {
		t.Errorf("Classify(%v) = %v, want ErrRejected", err, got)
	}
}

// TestClassifyConnectionRefused pins the retryable shape: a provider that is
// down now may be up in a second, so it gets a budget rather than a verdict.
func TestClassifyConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // free the port so the dial is refused rather than accepted

	resp, err := http.Get("http://" + addr + "/")
	if err == nil {
		resp.Body.Close()
		t.Fatal("request to a closed port succeeded")
	}
	if got := v1alpha1.Classify(err); got != v1.ErrProviderUnreachable {
		t.Errorf("Classify(%v) = %v, want ErrProviderUnreachable", err, got)
	}
}

// TestClassifyUnsupportedScheme pins the request libtunnel could not even
// build: a WithApiURL typo is configuration, not weather.
func TestClassifyUnsupportedScheme(t *testing.T) {
	resp, err := http.Post("gopher://example.invalid/tunnel", "application/json", nil)
	if err == nil {
		resp.Body.Close()
		t.Fatal("request with an unsupported scheme succeeded")
	}
	if got := v1alpha1.Classify(err); got != v1.ErrRejected {
		t.Errorf("Classify(%v) = %v, want ErrRejected", err, got)
	}
}

// TestClassifyIsIdempotent pins rule one: an error a provider already named
// comes back as it arrived, however deeply it is wrapped. This is what lets a
// backend tag the verdicts only its protocol can read and leave the rest here.
func TestClassifyIsIdempotent(t *testing.T) {
	for _, want := range []error{
		v1.ErrCertificate,
		v1.ErrRejected,
		v1.ErrCredentialRejected,
		v1.ErrProviderUnreachable,
		v1.ErrEdgeUnreachable,
		v1.ErrRateLimited,
		v1.ErrClosed,
	} {
		err := fmt.Errorf("unable to fetch tunnel spec: %w",
			fmt.Errorf("%w: %w", want, errors.New("cause")))
		if got := v1alpha1.Classify(err); got != want {
			t.Errorf("Classify(%v) = %v, want %v", err, got, want)
		}
	}
}

// TestClassifyNil pins that a nil error stays nil rather than becoming a
// failure — Classify is called on the error path, but defensively.
func TestClassifyNil(t *testing.T) {
	if got := v1alpha1.Classify(nil); got != nil {
		t.Errorf("Classify(nil) = %v, want nil", got)
	}
}

// TestClassifyUnknownIsRetryable pins the default. An error nothing recognizes
// must land in a class with a budget: that is what stops an unanticipated
// failure from looping forever, which is the whole complaint in #162.
func TestClassifyUnknownIsRetryable(t *testing.T) {
	got := v1alpha1.Classify(errors.New("something nobody anticipated"))
	if got != v1.ErrProviderUnreachable {
		t.Errorf("Classify(unknown) = %v, want ErrProviderUnreachable", got)
	}
	if v1.Budget(got) == 0 {
		t.Error("the default class has a zero budget; an unknown error would never be retried")
	}
}
