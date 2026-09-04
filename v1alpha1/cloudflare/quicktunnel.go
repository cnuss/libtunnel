package cloudflare

import (
	"context"
	"crypto/tls"
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

// recordHeader carries the provider's handle on the DNS record reserving a
// hostname, both ways: returned by a mint, sent back to resume it.
const recordHeader = "X-Record-Id"

// throttleReason renders a throttle's cause with the wait the provider asked
// for, so an error a caller reads carries the number it would otherwise have
// to find in a log line.
func throttleReason(after time.Duration, cause string) string {
	switch {
	case after > 0 && cause != "":
		return fmt.Sprintf("%s, resets in %s", cause, after)
	case after > 0:
		return fmt.Sprintf("resets in %s", after)
	case cause != "":
		return cause
	default:
		return "no rate-limit headers returned"
	}
}

// mintResult is one mint request's answer. record and after are set even when
// the request failed — the record so the next attempt resumes instead of
// minting again, after so it waits the interval the provider asked for.
type mintResult struct {
	spec   *Spec
	record string
	after  time.Duration
}

// budget is v1.Budget behind a package var so a test can shorten the retry
// budgets instead of sleeping through them. Production never reassigns it —
// this is the same seam shape QuickTunnelProvider.URL already is for the
// endpoint.
var budget = v1.Budget

// QuickTunnelProvider mints an anonymous *.tunneled.pizza tunnel from the
// quick-tunnel API, retrying with linear backoff until the context is done.
// Spec-field setters carried through Headers ride the request as reclaim
// hints, so a provider that reaps idle tunnels can hand the named tunnel back
// instead of minting fresh — see Spec.
type QuickTunnelProvider struct {
	// URL overrides the quick-tunnel API endpoint (synthesized from WithProvider
	// / its LIBTUNNEL__CLOUDFLARE_PROVIDER mirror, or set directly in tests).
	// Empty falls back to that environment mirror, then to the default —
	// unlike every other knob, a URL set here beats the environment, because
	// it is the seam a caller uses to point this provider at a specific
	// endpoint (a mock, an alternate API) rather than a configuration knob.
	URL string
	// Headers are added to the mint request (WithHeader / its
	// LIBTUNNEL__CLOUDFLARE_HEADERS mirror — see mintHeaders). They are
	// applied over the headers set here
	// (Content-Type, User-Agent), so a caller-supplied key replaces the
	// default for that key. Nil adds nothing.
	Headers http.Header
	// Log receives retry warnings. Nil is silent.
	Log *slog.Logger
	// record resumes a hostname minted earlier (X-Record-Id). Empty mints a
	// fresh one.
	record string
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
// A replayed spec's record id rides the request, naming the hostname to
// resume; without it the provider mints a fresh record and tunnel, so a retry
// that drops it costs a tunnel per attempt. A refused mint is terminal — the
// backend has judged the request it was given.
//
// A 429 is the provider's cadence, not a verdict. Carrying a spec it means the
// hostname does not resolve yet, and the record is replayed until it does;
// carrying an error it is the provider's own failure with the wait it wants.
// Either way Retry-After governs, bounded by the rate-limit budget.
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
			// The trust set libtunnel ships, not the host's alone: an image
			// with no ca-certificates package still verifies the mint
			// endpoint. Without this the edge connection would have verified
			// fine against the bundle compiled into the same binary while the
			// mint three files away could not (#164).
			TLSClientConfig: &tls.Config{RootCAs: caCertPool()},
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

	// fetch's middle result is the server-requested retry delay: a 429's
	// Retry-After when it carries one, zero otherwise.
	// fetch makes one mint request. record resumes a hostname when non-empty;
	// without it the provider mints a fresh record and tunnel, so a retry that
	// drops it costs a tunnel per attempt.
	fetch := func(record string) (mintResult, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
		if err != nil {
			return mintResult{}, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("User-Agent", fmt.Sprintf("cloudflared/%s", cloudflaredVersion))
		if record != "" {
			req.Header.Set(recordHeader, record)
		}
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
			return mintResult{}, fmt.Errorf("failed to request tunnel credentials: %w", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return mintResult{}, fmt.Errorf("failed to read tunnel credentials response: %w", err)
		}

		// Read off the headers before the body: a throttle can arrive with no
		// body at all — a proxy, a CDN, the endpoint's own per-IP cap — and it
		// is still a throttle, with a wait worth honoring.
		//
		// The record is carried whether or not this attempt succeeded. It
		// exists from the provider's first step, and the next attempt needs it
		// to resume rather than mint a second tunnel.
		out := mintResult{record: resp.Header.Get(recordHeader)}
		throttled := resp.StatusCode == http.StatusTooManyRequests
		if throttled {
			// The full header set, not just Retry-After: a fronted mint names
			// its throttle reason in provider-specific headers, and a silent
			// CI failure is diagnosed from exactly this line.
			log.Debug("quick tunnel mint throttled", "status", resp.StatusCode, "headers", resp.Header)
			raw := strings.TrimSpace(resp.Header.Get("Retry-After"))
			if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
				out.after = time.Duration(secs) * time.Second
			} else if when, err := http.ParseTime(raw); err == nil {
				// RFC 7231 also allows an HTTP-date form.
				if d := time.Until(when); d > 0 {
					out.after = d.Round(time.Second)
				}
			}
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
			if throttled {
				return out, fmt.Errorf("%w: %s", v1.ErrRateLimited, throttleReason(out.after, strings.TrimSpace(string(body))))
			}
			return out, fmt.Errorf("tunnel credentials request failed (status=%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		if data.Success {
			out.spec = &data.Result
			if !throttled {
				return out, nil
			}
			// The spec is complete and the tunnel exists; the hostname just
			// does not resolve yet. Replaying the record is idempotent, so
			// this waits it out rather than handing back a name that answers
			// nothing.
			return out, fmt.Errorf("%w: %s", v1.ErrRateLimited, throttleReason(out.after, "hostname not resolving yet"))
		}

		var errorMessages []string
		for _, e := range data.Errors {
			errorMessages = append(errorMessages, fmt.Sprintf("%d: %s", e.Code, e.Message))
		}
		joined := strings.Join(errorMessages, "; ")
		switch {
		case throttled:
			// Every failure the provider owns arrives this way, with the wait
			// it wants. Retryable by construction.
			return out, fmt.Errorf("%w: %s", v1.ErrRateLimited, throttleReason(out.after, joined))
		case resp.StatusCode < http.StatusInternalServerError:
			// A parsed success=false without a throttle is the API saying no,
			// not the API having a bad moment — retrying can't fix it.
			return out, fmt.Errorf("%w: %s", v1.ErrRejected, joined)
		default:
			return out, fmt.Errorf("tunnel credentials request failed: %s", joined)
		}
	}

	sleep := 0 * time.Second
	attempts := 0
	record := p.record
	// Each class keeps its own clock, started at its first failure, so a mint
	// that hits a rate limit and then a flaky resolver is not charged twice
	// for one slow start. The clock is wall time rather than a sum of the
	// backoff waits: three 15s timeouts cost 45s of real time but only 6s of
	// ramp, and a hang is exactly what the budget exists to catch.
	since := map[error]time.Time{}
	for {
		attempts++
		res, err := fetch(record)
		if res.record != "" {
			record = res.record
		}
		if err == nil {
			res.spec.RecordID = record
			return res.spec, nil
		}
		retryAfter := res.after

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
			// One class, two causes — a hostname still settling and a real
			// throttle both arrive as 429 with a wait. The error says which.
			log.Warn("mint asked us to wait, retrying...", "error", err, "nextAttemptIn", wait)
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
