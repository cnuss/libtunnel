package cloudflare

// Offline tests for the reverse-proxy shim (interposeReverseProxy). They build
// the proxy directly and speak plain HTTP to its listener address — no
// cloudflared, no tunnel mint, no real edge. There is no edge offline, so they
// cannot assert edge-flush timing; they assert the proxy relays the origin's
// response faithfully: right status, right framing, byte-identical body, and —
// for a streaming origin — every event delivered in order.

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// mustProxy interposes the reverse-proxy shim in front of srv and returns the
// http:// base URL a client dials.
func mustProxy(t *testing.T, ctx context.Context, srv *httptest.Server, flushInterval time.Duration) string {
	t.Helper()
	origin, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse origin url: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	addr, err := interposeReverseProxy(ctx, logger, origin, flushInterval)
	if err != nil {
		t.Fatalf("interposeReverseProxy: %v", err)
	}
	return "http://" + addr
}

func qint(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// TestPassthroughContentLength proves a FIXED (Content-Length) origin response
// is relayed VERBATIM through the shim: a normal, complete response — right
// status and a byte-identical body — not a mangled one.
func TestPassthroughContentLength(t *testing.T) { runPassthrough(t, false) }

// TestPassthroughContentLength_TLS is the regression for #106: an apiserver
// /healthz-shaped response (TLS origin, fixed Content-Length body "ok"). The
// shim must dial the origin over TLS (InsecureSkipVerify) and relay verbatim.
func TestPassthroughContentLength_TLS(t *testing.T) { runPassthrough(t, true) }

func runPassthrough(t *testing.T, useTLS bool) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A small, single write with no Flush lets net/http set a fixed
		// Content-Length (the non-chunked, /healthz shape).
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok")
	})
	var srv *httptest.Server
	if useTLS {
		srv = httptest.NewTLSServer(handler)
	} else {
		srv = httptest.NewServer(handler)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A non-zero flush interval must NOT affect a fixed response — it is one-shot.
	base := mustProxy(t, ctx, srv, 200*time.Millisecond)

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through shim failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 (verbatim relay of the fixed origin response)", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("body %q, want %q (relay must be byte-identical)", body, "ok")
	}
	if resp.ContentLength != 2 {
		t.Errorf("Content-Length %d, want 2 (fixed framing preserved verbatim)", resp.ContentLength)
	}
	if te := resp.TransferEncoding; len(te) != 0 {
		t.Errorf("Transfer-Encoding %v, want none (fixed response must not be re-chunked)", te)
	}
}

// streamEvent is one NDJSON event the streaming origin emits.
type streamEvent struct {
	Seq int    `json:"seq"`
	Ts  string `json:"ts"`
}

// TestStreamingPassthrough proves a chunked, unbuffered streaming origin
// response (the kube-watch shape) is proxied straight through with FlushInterval
// set: every event arrives, in order. There is no reconnect/session model
// anymore — this is a single straight stream through the reverse proxy.
func TestStreamingPassthrough(t *testing.T) {
	const total = 12
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		n := qint(r, "n", total)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fl.Flush()
		enc := json.NewEncoder(w) // appends '\n' -> NDJSON, like a watch stream
		for i := 0; i < n; i++ {
			if err := enc.Encode(streamEvent{Seq: i, Ts: time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
				return
			}
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	base := mustProxy(t, ctx, srv, 100*time.Millisecond)

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/watch?n="+strconv.Itoa(total), nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through shim failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}

	var ordered []int
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev streamEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("non-JSON line through the proxy (framing corrupted): %q", line)
		}
		ordered = append(ordered, ev.Seq)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("body read ended with %v (after %d events)", err, len(ordered))
	}

	if len(ordered) != total {
		t.Fatalf("collected %d events, want %d (a straight proxied stream must deliver all)", len(ordered), total)
	}
	for i, seq := range ordered {
		if seq != i {
			t.Fatalf("event %d arrived as seq %d — out of order", i, seq)
		}
	}
}
