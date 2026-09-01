package cloudflare

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
)

// quickTunnelURL is the public endpoint that mints anonymous quick tunnels.
const quickTunnelURL = "https://tunnel.pizza/tunnel"

// budget is v1.Budget behind a package var so a test can shorten the retry
// budgets instead of sleeping through them. Production never reassigns it —
// this is the same seam shape QuickTunnelProvider.URL already is for the
// endpoint.
var budget = v1.Budget

// QuickTunnelProvider mints an anonymous *.tunneled.pizza tunnel from the
// quick-tunnel API, retrying with linear backoff until the context is done.
// The most recently minted spec (latest.spec.json in the cache dir) seeds the
// request's reclaim hints, so a provider that reaps idle tunnels can hand the
// same tunnel back instead of minting fresh — see Spec.
type QuickTunnelProvider struct {
	// URL overrides the quick-tunnel API endpoint (synthesized from WithProvider
	// / its LIBTUNNEL__CLOUDFLARE_PROVIDER mirror, or set directly in tests).
	// Empty falls back to that environment mirror, then to the default —
	// unlike every other knob, a URL set here beats the environment, because
	// it is the seam a caller uses to point this provider at a specific
	// endpoint (a mock, an alternate API) rather than a configuration knob.
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
//
// The mint request carries reclaim hints (X-Id / X-Name / X-Secret) seeded
// from the most recently minted spec, latest.spec.json in the cache dir, for
// whichever of those keys Headers does not already set — the cache is a hint
// source, never credentials, and the backend decides whether to hand that
// tunnel back. A mint rejected while carrying cache-derived hints retries
// once, immediately, without them (the rejection judged the reclaim, not a
// fresh mint); a rejection with no cache hints in play stays terminal.
func (p *QuickTunnelProvider) Spec(ctx context.Context) (*Spec, error) {
	log := p.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	// A provider built directly (not through Backend.Provider, which applies
	// the same variable) still honors the environment mirror — the knob is
	// documented on v1.CloudflareProviderEnv without qualification, so a
	// direct QuickTunnel that ignored it would be a silent exception to
	// "every code knob has an env mirror".
	endpoint := p.URL
	if endpoint == "" {
		if host := os.Getenv(v1.CloudflareProviderEnv); host != "" {
			endpoint = providerEndpoint(host)
		}
	}
	if endpoint == "" {
		endpoint = quickTunnelURL
	}

	client := http.Client{
		Transport: &http.Transport{
			// Per-attempt bounds. The TLS handshake terminates at the
			// provider's edge and is quick regardless of load, so it stays
			// tight — a hung handshake is a dead endpoint, and failing fast
			// leaves budget for a retry. The response headers are the mint
			// itself: the endpoint holds the request while it mints and waits
			// out DNS propagation for the hostname, so the header wait must
			// cover a full server-side mint and the overall Timeout is the
			// real per-attempt bound.
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
		},
		Timeout: 15 * time.Second,
	}

	// Reclaim hints from the most recently minted spec (latest.spec.json,
	// #142): only for the hint keys p.Headers does not already carry — the
	// explicit spec-field setters and WithHeader land there and win. The
	// cache seeds hints, never credentials: the request always mints, and
	// the backend decides whether to hand the cached tunnel back.
	cacheHints := http.Header{}
	var cached Spec
	if v1alpha1.LatestSpec(backendName, &cached) {
		if cached.ID != "" && p.Headers.Get("X-Id") == "" {
			cacheHints.Set("X-Id", cached.ID)
		}
		if cached.Name != "" && p.Headers.Get("X-Name") == "" {
			cacheHints.Set("X-Name", cached.Name)
		}
		if len(cached.Secret) > 0 && p.Headers.Get("X-Secret") == "" {
			cacheHints.Set("X-Secret", base64.StdEncoding.EncodeToString(cached.Secret))
		}
	}

	// fetch's middle result is the server-requested retry delay: a 429's
	// Retry-After when it carries one, zero otherwise.
	fetch := func(hints http.Header) (*Spec, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("User-Agent", fmt.Sprintf("cloudflared/%s", cloudflaredVersion))
		for k, vs := range hints {
			req.Header[k] = vs
		}
		// Caller headers (WithHeader) apply over the defaults above — a supplied
		// key replaces the default for that key. (Cache hints never share a key
		// with them by construction.)
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
				return nil, d, fmt.Errorf("%w: resets in %s", v1.ErrRateLimited, d)
			}
			// RFC 7231 also allows an HTTP-date form.
			if when, err := http.ParseTime(retryAfter); err == nil {
				if d := time.Until(when); d > 0 {
					return nil, d, fmt.Errorf("%w: resets in %s", v1.ErrRateLimited, d.Round(time.Second))
				}
			}
			if retryAfter != "" {
				return nil, 0, fmt.Errorf("%w (HTTP 429): Retry-After=%s", v1.ErrRateLimited, retryAfter)
			}
			return nil, 0, fmt.Errorf("%w (HTTP 429): no rate-limit headers returned", v1.ErrRateLimited)
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
				return nil, 0, fmt.Errorf("%w: %s", v1.ErrRejected, strings.Join(errorMessages, "; "))
			}
			return nil, 0, fmt.Errorf("tunnel credentials request failed: %s", strings.Join(errorMessages, "; "))
		}
		return &data.Result, 0, nil
	}

	sleep := 0 * time.Second
	hints := cacheHints
	attempts := 0
	// Each class keeps its own clock, started at its first failure, so a mint
	// that hits a rate limit and then a flaky resolver is not charged twice
	// for one slow start. The clock is wall time rather than a sum of the
	// backoff waits: three 15s timeouts cost 45s of real time but only 6s of
	// ramp, and a hang is exactly what the budget exists to catch.
	since := map[error]time.Time{}
	for {
		attempts++
		spec, retryAfter, err := fetch(hints)
		if err == nil {
			return spec, nil
		}

		if errors.Is(err, v1.ErrRejected) && len(hints) > 0 {
			// The backend declined to hand the cached tunnel back (reaped
			// and unreclaimable, claimed elsewhere). That verdict is about
			// the reclaim, not about a fresh mint — retry once, immediately,
			// without the cache-derived hints. A rejection of the retry has
			// no hints left and falls through below, terminal, exactly as
			// when no cache was involved.
			log.Warn("cached spec refused by the mint provider, minting fresh", "error", err)
			hints = nil
			continue
		}

		class := v1alpha1.Classify(err)
		// named is err with its class attached — unless fetch already named
		// it, in which case attaching it again would only say the same thing
		// twice in the message.
		named := err
		if !errors.Is(err, class) {
			named = fmt.Errorf("%w: %w", class, err)
		}

		limit := budget(class)
		if limit == 0 {
			return nil, named
		}
		// A throttle that outlasts its own budget is reported now rather than
		// slept on: a caller can act on "resets in 5m", where waiting it out
		// just moves the hang somewhere the caller cannot see it.
		if retryAfter > limit {
			log.Warn("quick tunnel rate limited", "error", err, "resetsIn", retryAfter)
			return nil, named
		}
		if _, seen := since[class]; !seen {
			since[class] = time.Now()
		}
		// Checked before the wait, so the worst case is the budget plus one
		// attempt — a hung endpoint is reported at roughly budget + Timeout,
		// not at the budget exactly.
		if spent := time.Since(since[class]); spent > limit {
			return nil, fmt.Errorf("no spec after %d attempts in %s: %w",
				attempts, spent.Round(time.Second), named)
		}

		// The server's Retry-After wins over the linear ramp when it asks for
		// longer; either way the wait is bounded by ctx and by the budget.
		sleep += 1 * time.Second
		wait := max(sleep, retryAfter)
		if errors.Is(err, v1.ErrRateLimited) {
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
