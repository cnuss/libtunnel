package cloudflare

// Internal offline tests for the session shim (wrappedListener). They construct
// the private type directly and speak plain HTTP to its Addr() — no cloudflared,
// no tunnel mint, no real edge. Since there is no edge offline, they cannot
// assert edge-flush TIMING; instead they assert the shim's OUTPUT is correct:
// the right events, in order, exactly once. Any failure here is a shim bug, not
// an edge or network artifact.

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// streamEvent is one NDJSON event the test origin emits and the client decodes.
type streamEvent struct {
	Seq int    `json:"seq"`
	Ts  string `json:"ts"`
	Pad string `json:"pad,omitempty"`
}

// newStreamOrigin is a minimal kube-watch lookalike: a chunked application/json
// 200 that emits n events (default 10) as NDJSON, one per ms interval (default
// 100), each flushed immediately, with pad (default 0) filler bytes per event.
// It counts every request so a test can assert the shim shielded the origin to
// exactly one. It does NOT depend on testbed/main.go.
func newStreamOrigin(t *testing.T, useTLS bool) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		n := qint(r, "n", 10)
		ms := qint(r, "ms", 100)
		pad := qint(r, "pad", 0)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fl.Flush()

		enc := json.NewEncoder(w) // appends '\n' -> NDJSON, like a watch stream
		for i := 0; i < n; i++ {
			ev := streamEvent{Seq: i, Ts: time.Now().UTC().Format(time.RFC3339Nano)}
			if pad > 0 {
				ev.Pad = strings.Repeat("x", pad)
			}
			if err := enc.Encode(ev); err != nil {
				return // client hung up
			}
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Duration(ms) * time.Millisecond):
			}
		}
	})
	if useTLS {
		return httptest.NewTLSServer(handler), &hits
	}
	return httptest.NewServer(handler), &hits
}

// originHostPort strips the scheme from an httptest server URL, yielding the
// host:port the shim dials.
func originHostPort(u string) string {
	u = strings.TrimPrefix(u, "https://")
	return strings.TrimPrefix(u, "http://")
}

func qint(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// TestChopOffline exercises the clean-close (chop) edge-flush trigger. The
// client re-issues the identical URL (the kubectl re-watch shape); the session
// table reattaches it to the one live origin stream. It asserts every event is
// delivered exactly once and in order across >=3 short downstream responses,
// the origin saw exactly ONE request, and per-event latency is bounded by ~chop.
func TestChopOffline(t *testing.T) { runChopOffline(t, false) }

// TestChopOffline_TLS is the TLS analog of TestChopOffline: the chunked NDJSON
// watch origin terminates TLS with a self-signed cert. It proves the shim dials
// the origin over TLS (InsecureSkipVerify) and then de-chunks + chops exactly as
// on plaintext — same exactly-once ordering across reconnects, one origin conn.
func TestChopOffline_TLS(t *testing.T) { runChopOffline(t, true) }

func runChopOffline(t *testing.T, useTLS bool) {
	srv, hits := newStreamOrigin(t, useTLS)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const chop = 300 * time.Millisecond
	wl, err := newWrappedListener(ctx, logger, originHostPort(srv.URL), useTLS, chop)
	if err != nil {
		t.Fatalf("newWrappedListener: %v", err)
	}

	// The shim closes the conn after every short response; keep-alive reuse
	// would race that close, so force a fresh conn per request.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	// One logical watch: 12 events, 250ms apart (~3s of stream), requested with
	// the IDENTICAL url every time so reconnects reattach to the session.
	const (
		total    = 12
		interval = 250 * time.Millisecond
	)
	watchURL := "http://" + wl.Addr().String() + "/watch?n=12&ms=250"

	seen := map[int]bool{}
	var ordered []int
	var maxLat time.Duration
	requests := 0
	deadline := time.Now().Add(45 * time.Second)
	for len(seen) < total && time.Now().Before(deadline) {
		requests++
		for _, ev := range readResponse(t, ctx, client, watchURL) {
			if !seen[ev.seq] {
				seen[ev.seq] = true
				ordered = append(ordered, ev.seq)
				if ev.latency > maxLat {
					maxLat = ev.latency
				}
			}
		}
	}

	t.Logf("chop: collected %d/%d events over %d downstream responses; origin requests=%d; max per-event latency %v",
		len(seen), total, requests, hits.Load(), maxLat.Round(time.Millisecond))

	if len(seen) != total {
		t.Fatalf("collected %d events, want %d", len(seen), total)
	}
	for i, seq := range ordered {
		if seq != i {
			t.Fatalf("event %d arrived as seq %d — out of order or gapped across reconnects", i, seq)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("origin received %d requests, want exactly 1 (session must shield the origin)", got)
	}
	if requests < 3 {
		t.Errorf("only %d downstream response(s) for a %v stream with a %v chop — chop never cycled",
			requests, time.Duration(total)*interval, chop)
	}
	if limit := chop + time.Second; maxLat >= limit {
		t.Errorf("max per-event latency %v, want < %v (locally latency ≈ chop cadence)", maxLat, limit)
	}
}

// readEvent is one delivered event: its sequence number and end-to-end delivery
// latency (arrival − embedded origin ts; origin and client share the host clock).
type readEvent struct {
	seq     int
	latency time.Duration
}

// readResponse reads one (possibly short) downstream response and returns the
// events it carried. Unparsable lines (a boundary partial or a blank line) are
// skipped. A 1 MB scanner buffer covers long lines.
func readResponse(t *testing.T, ctx context.Context, client *http.Client, url string) []readEvent {
	t.Helper()
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		t.Logf("readResponse: build request: %v", err)
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		// Short responses and conn closes are the expected steady state here.
		t.Logf("readResponse: request ended: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var events []readEvent
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev streamEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue // partial or non-JSON line at a boundary; drop it
		}
		ts, err := time.Parse(time.RFC3339Nano, ev.Ts)
		if err != nil {
			continue
		}
		events = append(events, readEvent{seq: ev.Seq, latency: time.Since(ts)})
	}
	if err := sc.Err(); err != nil {
		t.Logf("readResponse: body read ended with %v (after %d events)", err, len(events))
	}
	return events
}

// TestPassthroughContentLength proves a FIXED (Content-Length) origin response
// is relayed VERBATIM through the flush-interval shim: the shim must NOT try to
// de-chunk it. The client sees a normal, complete response — right status and a
// byte-identical body — not a chunk-mangled one.
func TestPassthroughContentLength(t *testing.T) { runPassthrough(t, false) }

// TestPassthroughContentLength_TLS is the direct regression for #106: an
// apiserver /healthz-shaped response (TLS origin, fixed Content-Length body
// "ok"). Before the fix the shim TLS-mismatched the origin and mis-parsed the
// non-chunked body, 502-ing every request; now it dials the origin over TLS
// (InsecureSkipVerify) and relays the response verbatim.
func TestPassthroughContentLength_TLS(t *testing.T) { runPassthrough(t, true) }

func runPassthrough(t *testing.T, useTLS bool) {
	var hits atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// A non-zero chop must NOT affect a fixed response — it is relayed whole.
	wl, err := newWrappedListener(ctx, logger, originHostPort(srv.URL), useTLS, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("newWrappedListener: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	get := func() (*http.Response, string) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+wl.Addr().String()+"/healthz", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request through shim failed (502 shape): %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return resp, string(body)
	}

	resp, body := get()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 (verbatim relay of the fixed origin response)", resp.StatusCode)
	}
	if body != "ok" {
		t.Fatalf("body %q, want %q (relay must be byte-identical, not chunk-mangled)", body, "ok")
	}
	if resp.ContentLength != 2 {
		t.Errorf("Content-Length %d, want 2 (fixed framing preserved verbatim)", resp.ContentLength)
	}
	if te := resp.TransferEncoding; len(te) != 0 {
		t.Errorf("Transfer-Encoding %v, want none (fixed response must not be re-chunked)", te)
	}

	// A second identical request must start a FRESH session (the fixed session
	// finished on relay) and get the same complete response — not reattach to a
	// completed session and hang or 502.
	resp2, body2 := get()
	if resp2.StatusCode != http.StatusOK || body2 != "ok" {
		t.Fatalf("second request: status %d body %q, want 200 %q", resp2.StatusCode, body2, "ok")
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("origin saw %d requests, want 2 (each fixed response is its own one-shot session)", got)
	}
}
