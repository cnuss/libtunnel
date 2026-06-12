package cloudflare

import (
	"context"
	"encoding/json"
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

var _ v1.Provider[*v1.CloudflareSpec] = (*QuickTunnelProvider)(nil)

// Spec implements v1.Provider. It blocks until credentials are minted or ctx
// is done, backing off linearly between attempts (the API rate-limits).
func (p *QuickTunnelProvider) Spec(ctx context.Context) (*v1.CloudflareSpec, error) {
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

	fetch := func() (*v1.CloudflareSpec, error) {
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
				return nil, fmt.Errorf("tunnel rate limit resets in %s", humanize.RelTime(now.Add(time.Duration(secs)*time.Second), now, "", ""))
			}
			if retryAfter != "" {
				return nil, fmt.Errorf("tunnel rate limit hit (HTTP 429): Retry-After=%s", retryAfter)
			}
			return nil, fmt.Errorf("tunnel rate limit hit (HTTP 429): no rate-limit headers returned")
		}

		type response struct {
			Success bool `json:"success"`
			Errors  []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
			Result v1.CloudflareSpec `json:"result"`
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
		log.Warn("failed to fetch tunnel spec, retrying...", "error", err)

		sleep += 1 * time.Second
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
	}
}
