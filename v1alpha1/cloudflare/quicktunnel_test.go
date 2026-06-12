package cloudflare

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const specJSON = `{"success":true,"result":{
	"id":"00000000-0000-0000-0000-000000000000",
	"name":"test",
	"hostname":"test.trycloudflare.com",
	"account_tag":"tag",
	"secret":"c2VjcmV0"}}`

func TestQuickTunnelSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		w.Write([]byte(specJSON))
	}))
	defer srv.Close()

	spec, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Hostname != "test.trycloudflare.com" {
		t.Errorf("Hostname = %q", spec.Hostname)
	}
	if string(spec.Secret) != "secret" {
		t.Errorf("Secret = %q, want base64-decoded %q", spec.Secret, "secret")
	}
}

func TestQuickTunnelRetriesAfter429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(specJSON))
	}))
	defer srv.Close()

	spec, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("API called %d times, want 2 (one 429, one success)", got)
	}
	if spec.Hostname != "test.trycloudflare.com" {
		t.Errorf("Hostname = %q", spec.Hostname)
	}
}

func TestQuickTunnelRetriesAfterMalformedBody(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Write([]byte("<html>not json</html>"))
			return
		}
		w.Write([]byte(specJSON))
	}))
	defer srv.Close()

	if _, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("API called %d times, want 2 (one malformed, one success)", got)
	}
}

func TestQuickTunnelHonorsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success":false,"errors":[{"code":1,"message":"boom"}]}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if _, err := (&QuickTunnelProvider{URL: srv.URL}).Spec(ctx); err == nil {
		t.Fatal("Spec returned nil error although the API never succeeds and ctx expired")
	}
}

func TestQuickTunnelSurfacesRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	_, err := (&QuickTunnelProvider{URL: srv.URL, Log: log}).Spec(ctx)
	if !errors.Is(err, ErrRateLimited) {
		t.Errorf("err = %v, want errors.Is(_, ErrRateLimited)", err)
	}
	if !strings.Contains(buf.String(), "quick tunnel rate limited") {
		t.Errorf("no rate-limit warning logged; log output:\n%s", buf.String())
	}
}
