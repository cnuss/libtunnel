package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// quickTunnelURL is the public endpoint that mints anonymous quick tunnels.
const quickTunnelURL = "https://tunnel.pizza/tunnel"

// ErrRateLimited marks a quick-tunnel mint rejected with HTTP 429. The
// provider retries through it with backoff; it surfaces in the returned error
// chain when the context expires first.
var ErrRateLimited = errors.New("quick tunnel rate limited")

// ErrMintRejected marks a mint the API definitively refused (success=false on
// a non-5xx response). Retrying cannot fix it, so Spec returns immediately
// instead of backing off.
var ErrMintRejected = errors.New("quick tunnel mint rejected")

// QuickTunnelProvider mints an anonymous *.tunneled.pizza tunnel from the
// quick-tunnel API, retrying with linear backoff until the context is done.
type QuickTunnelProvider struct {
	// URL overrides the quick-tunnel API endpoint (synthesized from WithProvider
	// / its LIBTUNNEL__CLOUDFLARE_PROVIDER mirror, or set directly in tests).
	// Empty means the default.
	URL string
	// Headers are added to the mint request (WithHeader / its
	// LIBTUNNEL__CLOUDFLARE_HEADERS mirror, plus the backend's reclaim hints —
	// see mintHeaders). They are applied over the headers set here
	// (Content-Type, User-Agent), so a caller-supplied key replaces the
	// default for that key. Nil adds nothing.
	Headers http.Header
	// Log receives retry warnings. Nil is silent.
	Log *slog.Logger
}

// QuickTunnel returns a provider that mints anonymous quick tunnels.
func QuickTunnel() *QuickTunnelProvider {
	return &QuickTunnelProvider{}
}

var (
	_ v1.Provider[*Spec]    = (*QuickTunnelProvider)(nil)
	_ v1alpha1.LoggerSetter = (*QuickTunnelProvider)(nil)
)

// SetLogger adopts the tunnel's logger so retry warnings (rate limits
// especially) surface through it. An explicitly set Log wins.
func (p *QuickTunnelProvider) SetLogger(log *slog.Logger) {
	if p.Log == nil {
		p.Log = log
	}
}

// Spec implements v1.Provider. It blocks until credentials are minted or ctx
// is done, backing off linearly between attempts (the API rate-limits) — and
// when a 429 carries Retry-After (seconds or HTTP-date), the longer of the
// two waits is honored.
func (p *QuickTunnelProvider) Spec(ctx context.Context) (*Spec, error) {
	log := p.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	endpoint := p.URL
	if endpoint == "" {
		endpoint = quickTunnelURL
	}

	client := http.Client{
		Transport: &http.Transport{
			// Per-attempt bounds, deliberately tight: a saturated mint
			// endpoint that holds the connection instead of shedding a 429 (a
			// serverless provider at its concurrency limit) must not eat a
			// caller's whole budget in one attempt — failing fast and
			// retrying gives more chances to land on free capacity. A healthy
			// mint answers well inside these.
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
		},
		Timeout: 15 * time.Second,
	}

	// fetch's middle result is the server-requested retry delay: a 429's
	// Retry-After when it carries one, zero otherwise.
	fetch := func() (*Spec, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("User-Agent", fmt.Sprintf("cloudflared/%s", cloudflaredVersion))
		// Caller headers (WithHeader) apply over the defaults above — a supplied
		// key replaces the default for that key.
		for k, vs := range p.Headers {
			req.Header.Del(k)
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to request tunnel credentials: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read tunnel credentials response: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			// The full header set, not just Retry-After: a fronted mint (a
			// serverless provider, a proxy) names its throttle reason in
			// provider-specific headers, and a silent CI failure is diagnosed
			// from exactly this line.
			log.Debug("quick tunnel mint rate limited", "status", resp.StatusCode, "headers", resp.Header)
			retryAfter := strings.TrimSpace(resp.Header.Get("Retry-After"))
			if secs, err := strconv.Atoi(retryAfter); err == nil && secs > 0 {
				d := time.Duration(secs) * time.Second
				return nil, d, fmt.Errorf("%w: resets in %s", ErrRateLimited, d)
			}
			// RFC 7231 also allows an HTTP-date form.
			if when, err := http.ParseTime(retryAfter); err == nil {
				if d := time.Until(when); d > 0 {
					return nil, d, fmt.Errorf("%w: resets in %s", ErrRateLimited, d.Round(time.Second))
				}
			}
			if retryAfter != "" {
				return nil, 0, fmt.Errorf("%w (HTTP 429): Retry-After=%s", ErrRateLimited, retryAfter)
			}
			return nil, 0, fmt.Errorf("%w (HTTP 429): no rate-limit headers returned", ErrRateLimited)
		}

		type response struct {
			Success bool `json:"success"`
			Errors  []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
			Result Spec `json:"result"`
		}

		var data response
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, 0, fmt.Errorf("tunnel credentials request failed (status=%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		if !data.Success {
			var errorMessages []string
			for _, e := range data.Errors {
				errorMessages = append(errorMessages, fmt.Sprintf("%d: %s", e.Code, e.Message))
			}
			// A parsed success=false on a non-5xx response is the API saying
			// no, not the API having a bad moment — retrying can't fix it.
			if resp.StatusCode < http.StatusInternalServerError {
				return nil, 0, fmt.Errorf("%w: %s", ErrMintRejected, strings.Join(errorMessages, "; "))
			}
			return nil, 0, fmt.Errorf("tunnel credentials request failed: %s", strings.Join(errorMessages, "; "))
		}
		return &data.Result, 0, nil
	}

	sleep := 0 * time.Second
	for {
		spec, retryAfter, err := fetch()
		if err == nil {
			return spec, nil
		}
		if errors.Is(err, ErrMintRejected) {
			return nil, err
		}
		// The server's Retry-After wins over the linear ramp when it asks for
		// longer; either way the wait is bounded by ctx below.
		sleep += 1 * time.Second
		wait := max(sleep, retryAfter)
		if errors.Is(err, ErrRateLimited) {
			log.Warn("quick tunnel rate limited, retrying...", "error", err, "nextAttemptIn", wait)
		} else {
			log.Warn("failed to fetch tunnel spec, retrying...", "error", err)
		}

		select {
		case <-ctx.Done():
			// Keep the last fetch failure in the chain so callers can see
			// (and errors.Is) why minting never succeeded.
			return nil, errors.Join(ctx.Err(), err)
		case <-time.After(wait):
		}
	}
}
