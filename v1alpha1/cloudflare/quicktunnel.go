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

	"github.com/dustin/go-humanize"

	v1 "github.com/cnuss/libtunnel/v1"
)

// quickTunnelURL is the public endpoint that mints anonymous quick tunnels.
const quickTunnelURL = "https://api.trycloudflare.com/tunnel"

// ErrRateLimited marks a quick-tunnel mint rejected with HTTP 429. The
// provider retries through it with backoff; it surfaces in the returned error
// chain when the context expires first.
var ErrRateLimited = errors.New("quick tunnel rate limited")

// QuickTunnelProvider mints an anonymous *.trycloudflare.com tunnel from the
// quick-tunnel API, retrying with linear backoff until the context is done.
type QuickTunnelProvider struct {
	// URL overrides the quick-tunnel API endpoint (tests).
	URL string
	// Log receives retry warnings. Nil is silent.
	Log *slog.Logger
}

// QuickTunnel returns a provider that mints anonymous quick tunnels.
func QuickTunnel() *QuickTunnelProvider {
	return &QuickTunnelProvider{}
}

var _ v1.Provider[*Spec] = (*QuickTunnelProvider)(nil)

// SetLogger adopts the tunnel's logger so retry warnings (rate limits
// especially) surface through it. An explicitly set Log wins.
func (p *QuickTunnelProvider) SetLogger(log *slog.Logger) {
	if p.Log == nil {
		p.Log = log
	}
}

// Spec implements v1.Provider. It blocks until credentials are minted or ctx
// is done, backing off linearly between attempts (the API rate-limits).
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
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		},
		Timeout: 15 * time.Second,
	}

	fetch := func() (*Spec, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("User-Agent", fmt.Sprintf("cloudflared/%s", cloudflaredVersion))

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to request tunnel credentials: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read tunnel credentials response: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			if secs, err := strconv.Atoi(retryAfter); err == nil {
				now := time.Now()
				return nil, fmt.Errorf("%w: resets in %s", ErrRateLimited, humanize.RelTime(now.Add(time.Duration(secs)*time.Second), now, "", ""))
			}
			if retryAfter != "" {
				return nil, fmt.Errorf("%w (HTTP 429): Retry-After=%s", ErrRateLimited, retryAfter)
			}
			return nil, fmt.Errorf("%w (HTTP 429): no rate-limit headers returned", ErrRateLimited)
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
			return nil, fmt.Errorf("tunnel credentials request failed (status=%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		if !data.Success {
			var errorMessages []string
			for _, e := range data.Errors {
				errorMessages = append(errorMessages, fmt.Sprintf("%d: %s", e.Code, e.Message))
			}
			return nil, fmt.Errorf("tunnel credentials request failed: %s", strings.Join(errorMessages, "; "))
		}
		return &data.Result, nil
	}

	sleep := 0 * time.Second
	for {
		spec, err := fetch()
		if err == nil {
			return spec, nil
		}
		if errors.Is(err, ErrRateLimited) {
			log.Warn("quick tunnel rate limited, retrying...", "error", err, "nextAttemptIn", sleep+time.Second)
		} else {
			log.Warn("failed to fetch tunnel spec, retrying...", "error", err)
		}

		sleep += 1 * time.Second
		select {
		case <-ctx.Done():
			// Keep the last fetch failure in the chain so callers can see
			// (and errors.Is) why minting never succeeded.
			return nil, errors.Join(ctx.Err(), err)
		case <-time.After(sleep):
		}
	}
}
