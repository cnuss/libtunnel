// Package cloudflare is the Cloudflare backend for libtunnel: a cloudflared
// quick-tunnel engine driven entirely in-process (no cloudflared binary). It
// implements the v1alpha1 Engine contract; obtain it through the façade
// constructor libtunnel.Cloudflare().
package cloudflare

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/cloudflared/client"
	"github.com/cloudflare/cloudflared/config"
	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/edgediscovery"
	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
	"github.com/cloudflare/cloudflared/features"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/ingress/origins"
	"github.com/cloudflare/cloudflared/orchestration"
	"github.com/cloudflare/cloudflared/signal"
	"github.com/cloudflare/cloudflared/supervisor"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare/probe"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare/spec"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare/trust"
)

// cloudflaredVersion is reported to the edge as the connector version —
// inferred from the cloudflared module in the build info so it tracks go.mod
// instead of drifting in a hand-maintained constant.
var cloudflaredVersion = func() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/cloudflare/cloudflared" {
				return dep.Version
			}
		}
	}
	return "unknown"
}()

// libtunnelVersion is this module's version from the build info, so the
// User-Agent tracks releases rather than a constant.
var libtunnelVersion = sync.OnceValue(func() string {
	version := "devel"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/cnuss/libtunnel" {
				if dep.Replace != nil {
					dep = dep.Replace
				}
				if dep.Version != "" {
					version = dep.Version
				}
			}
		}
	}
	return version
})

// agentPlatform closes the User-Agent comment on every mint request and in
// the NEL reports posted to a provider's collector: what the client runs on.
var agentPlatform = sync.OnceValue(func() string {
	return fmt.Sprintf("%s/%s; %s", runtime.GOOS, runtime.GOARCH, runtime.Version())
})

// promMu serializes the prometheus.DefaultRegisterer swap below: cloudflared
// registers metrics against the global registerer at construction, which
// would collide across tunnels (and pollute the host application's metrics).
var promMu sync.Mutex

// backendName tags specs minted by this backend (Name, Serialize, the
// LIBTUNNEL_SPEC envelope) — one source of truth so the tag never drifts.
const backendName = spec.Backend

// Spec is the Cloudflare backend's credential set, defined in the spec
// package so that everything under this directory can name it without
// importing the engine; an alias, so it is the same type here.
type Spec = spec.Spec

// RecordIDKey is spec.RecordIDKey, the metadata key the hostname's record
// rides under.
const RecordIDKey = spec.RecordIDKey

// goneProbeDelay is how long the tunnel may have no connection at all before
// the edge is asked whether it still has the tunnel. Long enough that an
// ordinary reconnect — cloudflared's first backoff is a second — is over
// before anything is asked.
const goneProbeDelay = 30 * time.Second

// originDNSResolver is the address cloudflared's DNS origin service would
// resolve to on its own: the local resolver on the standard port. Unused
// here, but the service wants one.
var originDNSResolver = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 53)

// gracePeriod bounds the graceful shutdown: how long in-flight requests get
// to finish once the tunnel ends and its connections are unregistered, and
// so how long Done can take. cloudflared's own default (its --grace-period).
const gracePeriod = 30 * time.Second

// haConnections is the number of edge (HA) connections the supervisor keeps.
// The reconnect lever fires one ReconnectSignal per conn to cycle them all.
const haConnections = 2

// edgeWatcher tracks the tunnel's edge connections from the Observer sink:
// Connected events, so a caller can wait for N of them past a barrier, and the
// failed attempts between them.
//
// The sink calls up on every Connected; generation returns the running count
// plus a channel that closes on the next one. Because each delivered
// ReconnectSignal breaks exactly one edge conn and thus yields exactly one
// Connected, waiting for the count to advance by haConnections is a correct
// "all cycled conns are back up" barrier for any HA count.
//
// The sink calls attempt on every Reconnecting, which the supervisor sends
// before each backoff — including after a dial that never connected, so before
// the first Connected the count is failed attempts to reach the edge, which is
// what the ErrEdgeUnreachable bound reports.
//
// It calls disconnect on every Disconnected, which the supervisor defers around
// each serve attempt. That fires whether or not the attempt ever connected, so
// the count says how many serve attempts ended — not how many live connections
// were lost, and not why.
type edgeWatcher struct {
	mu  sync.Mutex
	gen uint64
	ch  chan struct{}
	// Per connection index, so the watcher knows which connections are up
	// now and not only which have ever been. HA keeps every map to a
	// handful.
	attempts    map[uint8]uint64
	disconnects map[uint8]uint64
	// live is the connection indexes registered right now, so "every
	// connection is up" and "none is" are each a count.
	live map[uint8]bool
}

func newEdgeWatcher() *edgeWatcher { return &edgeWatcher{ch: make(chan struct{})} }

func (e *edgeWatcher) generation() (uint64, <-chan struct{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gen, e.ch
}

// up records a Connected for index. Both results are transitions, not
// states: alive reports that this registration is the first live connection
// — at startup, or after every connection had dropped — and full that it
// brought every HA connection up. A listener hears each once per time it
// happens rather than once per registration.
func (e *edgeWatcher) up(index uint8) (alive, full bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gen++
	close(e.ch)
	e.ch = make(chan struct{})
	if e.live == nil {
		e.live = map[uint8]bool{}
	}
	wasEmpty := len(e.live) == 0
	wasFull := len(e.live) >= haConnections
	e.live[index] = true
	return wasEmpty, !wasFull && len(e.live) >= haConnections
}

func (e *edgeWatcher) attempt(index uint8) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.attempts == nil {
		e.attempts = map[uint8]uint64{}
	}
	e.attempts[index]++
}

// disconnect records that index's connection ended, freeing its slot in the
// live set. empty reports that this was the last one — the transition to no
// connection at all, so a drop that leaves others up is not reported, and
// neither is an attempt ending that never registered to begin with.
func (e *edgeWatcher) disconnect(index uint8) (empty bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.disconnects == nil {
		e.disconnects = map[uint8]uint64{}
	}
	e.disconnects[index]++
	wasEmpty := len(e.live) == 0
	delete(e.live, index)
	return !wasEmpty && len(e.live) == 0
}

// liveCount is how many connections are registered right now.
func (e *edgeWatcher) liveCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.live)
}

func (e *edgeWatcher) disconnectCount() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	var n uint64
	for _, c := range e.disconnects {
		n += c
	}
	return n
}

func (e *edgeWatcher) attemptCount() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	var n uint64
	for _, c := range e.attempts {
		n += c
	}
	return n
}

// edgeEventName renders an Observer event for a log line. cloudflared's Status
// is an unnamed int, so an unrecognized one is reported as itself rather than
// guessed at.
func edgeEventName(s connection.Status) string {
	switch s {
	case connection.Connected:
		return "connected"
	case connection.Disconnected:
		return "disconnected"
	case connection.Reconnecting:
		return "reconnecting"
	case connection.RegisteringTunnel:
		return "registering"
	case connection.Unregistering:
		return "unregistering"
	case connection.SetURL:
		return "set-url"
	default:
		return fmt.Sprintf("status(%d)", int(s))
	}
}

// Backend is the cloudflared quick-tunnel engine. It carries the origin-scheme
// settings declared via WithTLS / WithHTTP2; obtain a fresh one per tunnel from
// libtunnel.Cloudflare(). Both settings default false, and both can be fixed
// from the environment (LIBTUNNEL_TLS / LIBTUNNEL_HTTP2) — a fixed knob makes
// its mutator a no-op.
type Backend struct {
	tls        bool
	tlsFixed   bool
	http2      bool
	http2Fixed bool
	// envErr is the first unparsable env knob, surfaced at connect: an
	// operator override that can't be honored fails the tunnel loudly instead
	// of being silently ignored.
	envErr error
	// fields carries the spec-field setters (WithID and friends), laid over
	// the hint at mint time.
	fields Spec
	// hints is the spec being replayed (From): the base of the mint request's
	// hint. Nil unless this backend is a replay.
	hints *Spec
	// providerHost overrides the quick-tunnel mint provider host (WithProvider);
	// the endpoint https://<host>/tunnel is synthesized from it (a value carrying
	// a scheme is used verbatim). Empty means the default (tunnel.pizza);
	// v1.CloudflareProviderEnv supersedes either.
	providerHost string
	// edgeProtocol pins the edge transport (WithEdgeProtocol). Empty leaves the
	// choice to cloudflared; v1.CloudflareEdgeProtocolEnv supersedes either.
	edgeProtocol EdgeProtocol
	// headers carries request headers added to the quick-tunnel mint call via
	// WithHeader. Nil until the first WithHeader; overlaid by (and augmented
	// with) v1.CloudflareHeadersEnv at mint time.
	headers http.Header
	// token is the mint request credential (WithToken), sent as
	// "Authorization: token <value>". Empty sends none; v1.TokenEnv
	// supersedes either.
	token string
	// Runtime state wired at connect. reconnected feeds the supervisor's
	// external-control channel, edge tracks edge connections, and reconnectCtx
	// is the tunnel context Reconnect waits on. All nil until connect runs.
	reconnected  chan supervisor.ReconnectSignal
	edge         *edgeWatcher
	reconnectCtx context.Context
	// stopped closes once the supervisor has returned: its edge connections
	// unregistered and closed, or the grace period spent. Nil until connect.
	stopped chan struct{}
	// prober is the one asker for this backend: the hint probe and the edge
	// watcher share it, so what the first learned about the network — the
	// route to the edge, the TLS configs — is not learned twice.
	prober *probe.Prober
	// establishInterval is fixed at construction rather than read by the
	// establish loop: the loop is a goroutine that may start after the
	// caller has moved on, and a test shortening the package default for
	// the next tunnel must not race a goroutine the last one left behind.
	establishInterval time.Duration
	// establishing is set while a loop-through is in flight, so a second
	// trigger while one runs does not double it — the one running will
	// succeed on the new connection anyway.
	establishing atomic.Bool
}

// Stopped closes once the edge has been let go of (nil before connect).
// Implements the v1alpha1 Engine contract.
func (b *Backend) Stopped() <-chan struct{} { return b.stopped }

// New returns the Cloudflare backend. The origin-scheme knobs are fixed from
// the environment here when LIBTUNNEL_TLS / LIBTUNNEL_HTTP2 are set. The first
// unparsable value wins and is surfaced at connect.
func New() *Backend {
	b := &Backend{
		establishInterval: establishInterval,
		prober:            probe.New(),
	}
	b.tls, b.tlsFixed, b.envErr = v1alpha1.EnvBool(v1.TLSEnv)
	if b.envErr == nil {
		b.http2, b.http2Fixed, b.envErr = v1alpha1.EnvBool(v1.HTTP2Env)
	}
	return b
}

// From returns a Cloudflare backend that replays spec: it rides the mint
// request as the hint, so the provider hands the same tunnel back when it
// still exists. It backs libtunnel.From.
//
// The provider always answers with a working spec, substituting when the
// original is gone. A substitution that keeps the hostname is honored
// silently — the identity a caller serves on survived, and only the tunnel
// behind it is new. One that does not is reported (see hinted): a caller
// replaying a specific spec is owed that news here, in one round trip, rather
// than at the edge thirty seconds later.
//
// It sits at the end of the env chain, so LIBTUNNEL_SPEC and LIBTUNNEL_FROM
// still override it (env beats code).
func From(spec *Spec) *Backend {
	b := New()
	b.hints = spec
	return b
}

// WithTLS declares whether the origin terminates TLS (https vs http ingress).
// Default false. A no-op when LIBTUNNEL_TLS fixed the knob from the
// environment. Returns the backend for chaining.
func (b *Backend) WithTLS(tls bool) v1.Backend[*Spec] {
	if !b.tlsFixed {
		b.tls = tls
	}
	return b
}

// WithHTTP2 declares whether the origin is dialed over HTTP/2. Default false.
// A no-op when LIBTUNNEL_HTTP2 fixed the knob from the environment. Returns
// the backend for chaining.
func (b *Backend) WithHTTP2(http2 bool) v1.Backend[*Spec] {
	if !b.http2Fixed {
		b.http2 = http2
	}
	return b
}

// Reconnect forcefully cycles the cloudflared<->edge tunnel(s) and blocks until
// they are re-established, ctx is done, or the tunnel shuts down (see
// v1.Backend.Reconnect). It fires one ReconnectSignal per HA connection, then
// waits for haConnections Connected events past the pre-send count — each
// delivered signal breaks exactly one edge conn and thus yields exactly one
// Connected, so the barrier is correct for any HA count. Errors if called before
// the tunnel has connected.
func (b *Backend) Reconnect(ctx context.Context) error {
	if b.reconnected == nil || b.edge == nil || b.reconnectCtx == nil {
		return fmt.Errorf("cloudflare: Reconnect before tunnel connected")
	}
	// Wait on the caller's ctx (its deadline/cancellation) and on the tunnel
	// context, so a tunnel teardown mid-reconnect unblocks even if ctx does not.
	done := b.reconnectCtx.Done()
	base, _ := b.edge.generation()
	for range haConnections {
		select {
		case b.reconnected <- supervisor.ReconnectSignal{}:
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return b.reconnectCtx.Err()
		}
	}
	for {
		gen, ch := b.edge.generation()
		if gen-base >= haConnections {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
			return b.reconnectCtx.Err()
		}
	}
}

// The spec-field setters are hints: each rides the mint request as a header,
// over the same field of whatever spec the chain is replaying — a caller
// naming a field outright means it. None is stamped onto the result; the
// provider's answer is the spec. Each is superseded by its
// LIBTUNNEL__CLOUDFLARE_* variable (env beats code). They return the concrete
// backend, so chain them before the v1.Backend mutators (WithTLS, WithHTTP2),
// which return the interface.

// WithRecordID names the provider's record for the hostname the mint should
// resume — the one hint tunnel.pizza reads (see Spec.RecordID). Env mirror:
// LIBTUNNEL__CLOUDFLARE_RECORD_ID.
func (b *Backend) WithRecordID(record string) *Backend {
	b.fields.WithMeta(RecordIDKey, record)
	return b
}

// WithID names the tunnel (a UUID) the mint should hand back. Env mirror:
// LIBTUNNEL__CLOUDFLARE_ID.
func (b *Backend) WithID(id string) *Backend {
	b.fields.ID = id
	return b
}

// WithName overrides the tunnel name. Env mirror: LIBTUNNEL__CLOUDFLARE_NAME.
func (b *Backend) WithName(name string) *Backend {
	b.fields.Name = name
	return b
}

// WithHostname overrides the public hostname. Env mirror:
// LIBTUNNEL__CLOUDFLARE_HOSTNAME.
func (b *Backend) WithHostname(hostname string) *Backend {
	b.fields.Hostname = hostname
	return b
}

// WithAccountTag overrides the account tag. Env mirror:
// LIBTUNNEL__CLOUDFLARE_ACCOUNT_TAG.
func (b *Backend) WithAccountTag(tag string) *Backend {
	b.fields.AccountTag = tag
	return b
}

// WithSecret overrides the tunnel secret. Env mirror:
// LIBTUNNEL__CLOUDFLARE_SECRET (base64, the JSON []byte encoding).
func (b *Backend) WithSecret(secret []byte) *Backend {
	b.fields.Secret = secret
	return b
}

// WithProvider overrides the quick-tunnel mint provider host (default
// tunnel.pizza); the endpoint https://<host>/tunnel is synthesized
// from it — pass just the host, the scheme and path are assumed. A value that
// carries a scheme (e.g. http://127.0.0.1:8080/tunnel) is used verbatim, for
// pointing the mint at a mock or alternate endpoint. Env mirror:
// LIBTUNNEL__CLOUDFLARE_PROVIDER (env beats code).
func (b *Backend) WithProvider(host string) *Backend {
	b.providerHost = host
	return b
}

// EdgeProtocol is a transport cloudflared can use to reach the tunnel edge.
type EdgeProtocol string

const (
	// EdgeQUIC reaches the edge over UDP. The edge closes a QUIC connection
	// when the tunnel behind it goes away, so a client learns in seconds what
	// http2 leaves it to discover minutes later.
	EdgeQUIC EdgeProtocol = "quic"
	// EdgeHTTP2 reaches the edge over TCP, which works on networks that drop
	// UDP.
	EdgeHTTP2 EdgeProtocol = "http2"
	// EdgeAuto leaves the choice, and the fallback, to cloudflared.
	EdgeAuto EdgeProtocol = "auto"
)

// WithEdgeProtocol pins the edge transport. Unset, cloudflared chooses and
// falls back on its own, which is the right default: it knows QUIC to http2,
// and it is the thing holding the connection when a transport turns out not to
// work.
//
// Pin EdgeHTTP2 on a network known to drop UDP, where the fallback would
// otherwise cost a minute before landing there anyway. Pin EdgeQUIC to refuse
// that fallback, keeping the signal http2 does not carry.
//
// Not to be confused with WithHTTP2, which is about the other end of the
// tunnel — whether the origin is dialed over HTTP/2.
//
// Env mirror: LIBTUNNEL__CLOUDFLARE_EDGE_PROTOCOL (env beats code). An
// unrecognized protocol fails the tunnel at connect rather than falling back
// silently — naming a transport means it.
func (b *Backend) WithEdgeProtocol(p EdgeProtocol) *Backend {
	b.edgeProtocol = p
	return b
}

// resolveEdgeProtocol reports the transport to hand cloudflared: the env
// mirror over the code value, and EdgeAuto when neither is set.
func (b *Backend) resolveEdgeProtocol() (EdgeProtocol, error) {
	p := b.edgeProtocol
	if raw := strings.TrimSpace(os.Getenv(v1.CloudflareEdgeProtocolEnv)); raw != "" {
		p = EdgeProtocol(raw)
	}
	switch p {
	case "":
		return EdgeAuto, nil
	case EdgeQUIC, EdgeHTTP2, EdgeAuto:
		return p, nil
	default:
		return "", fmt.Errorf("unknown edge protocol %q, want one of %q, %q, %q", p, EdgeQUIC, EdgeHTTP2, EdgeAuto)
	}
}

// WithHeader adds a request header to the quick-tunnel mint call, so a provider
// can vary what it returns based on the request (e.g. X-Opaque: true asking for
// a less-guessable hostname). Repeatable — successive calls accumulate, and
// repeating a key adds another value. Env mirror: LIBTUNNEL__CLOUDFLARE_HEADERS,
// a comma-separated K=V list, whose entries beat code per key. Applied over the
// headers the mint sets itself (Content-Type, User-Agent) and over the hint
// headers, so a caller may override any of them. User-Agent is the exception
// that keeps a part: the caller's value replaces the product token, and the
// "(libtunnel/<version>; <os>/<arch>; <go>)" comment still follows it.
// The comment drops its libtunnel entry when the product token is already
// libtunnel/….
func (b *Backend) WithHeader(key, value string) *Backend {
	if b.headers == nil {
		b.headers = http.Header{}
	}
	b.headers.Add(key, value)
	return b
}

// AddHeader is WithHeader for the core's engine contract: Tunnel.WithHeader
// reaches the backend through it, so a tunnel built by From — whose backend
// the caller never holds — can still carry headers on the mint.
func (b *Backend) AddHeader(key, value string) { b.WithHeader(key, value) }

// WithToken sets the credential the mint request carries, as "Authorization:
// token <value>", so a provider that gates minting can tell who is asking.
// Applied with the mint's own defaults (Content-Type, User-Agent), so an
// explicit WithHeader("Authorization", …) or the LIBTUNNEL__CLOUDFLARE_HEADERS
// mirror replaces it, the way they replace every default. Sent to
// tunnel.pizza only: any other endpoint (WithProvider) could replay it, so it
// gets none. Env mirror: LIBTUNNEL_TOKEN (env beats code). Never part of the
// spec or its handoff.
func (b *Backend) WithToken(token string) v1.Backend[*Spec] {
	b.token = token
	return b
}

var (
	_ v1.Backend[*Spec]      = (*Backend)(nil)
	_ v1alpha1.Engine[*Spec] = (*Backend)(nil)
	_ v1.Tunnel              = (*v1alpha1.TunnelImpl[*Spec])(nil)
)

// Name implements v1.Backend.
func (b *Backend) Name() string {
	return backendName
}

// Provider is the Cloudflare credential chain. What the process already
// knows about the tunnel (see hint) is put to the edge first: live and
// unserved, it is the spec; served by another connector, the tunnel fails;
// otherwise it rides the mint request as hints and the provider's answer is
// the spec. Either way the answer is exported for children to inherit.
func (b *Backend) Provider() v1.Provider[*Spec] {
	host := b.providerHost
	stringEnv(v1.CloudflareProviderEnv, &host) // env beats code
	qt := QuickTunnel()
	if host != "" {
		qt.URL = providerEndpoint(host)
	}
	// The bridge lives on the provider's host: the one host a network that
	// allows nothing else already had to allow, for the mint. The mint
	// applies its default endpoint lazily, so it is applied here too.
	b.prober.WithBridge(bridgeFor(cmp.Or(qt.URL, quickTunnelURL)))
	qt.Headers = mintHeaders(b.headers)
	qt.Token = b.token
	return v1alpha1.Export(backendName, &hinted{backend: b, mint: qt})
}

// hinted resolves the hint at fetch time — the environment is read where it
// takes effect, like every other knob — hands it to the mint, and reports
// what the mint made of it.
//
// It does not reject a substitute. By the time it runs the mint has happened
// and a real tunnel exists, so refusing the spec strands that tunnel and
// leaves the caller no move but to mint a second one for the new hostname it
// was already being handed (#175).
//
// When nothing answers at all and the hint is a complete credential set, the
// hint is served as given: an endpoint that never answered is not a verdict
// on the spec, and a spec that turns out to be dead fails at the edge, which
// is where it failed before any of this. An incomplete hint has nothing to
// serve, and the unreachable error stands.
type hinted struct {
	backend *Backend
	mint    *QuickTunnelProvider
	log     *slog.Logger
}

// SetLogger keeps the tunnel's logger for the notices below and forwards it to
// the mint.
func (p *hinted) SetLogger(log *slog.Logger) {
	p.log = log
	p.mint.SetLogger(log)
}

func (p *hinted) Spec(ctx context.Context) (*Spec, error) {
	hint, err := p.backend.hint()
	if err != nil {
		return nil, err
	}
	log := p.log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	// A hint that could register is put to the edge before any mint: the
	// edge, not the provider and not this library, knows whether the tunnel
	// is up. Vouched for, it is the spec and the provider is never asked.
	complete := hint.ID != "" && hint.Hostname != "" && hint.AccountTag != "" && len(hint.Secret) > 0
	if complete {
		switch err := probeHint(ctx, p.backend.prober, hint, log); {
		case err == nil:
			log.Info("edge vouched for the spec, using it as given", "hostname", hint.Hostname)
			return hint, nil
		case errors.Is(err, probe.ErrInUse):
			return nil, fmt.Errorf("%w: %w", v1.ErrInUse, err)
		default:
			log.Debug("edge did not vouch for the spec, minting with it as the hint", "error", err)
		}
	}

	p.mint.hint = hint
	got, err := p.mint.Spec(ctx)
	if err != nil {
		if !complete || !errors.Is(err, v1.ErrProviderUnreachable) {
			return nil, err
		}
		p.logf("mint provider unreachable, using the spec as given", "error", err,
			"hostname", hint.Hostname)
		return hint, nil
	}

	switch {
	case hint.Hostname == "" || got == nil:
	case got.Hostname != hint.Hostname:
		// The reservation is gone. The hostname changes whether or not this
		// spec is used, so a caller holding the old one needs telling — it is
		// the only notice it gets.
		p.logf("hinted hostname is gone, adopting the one minted for it",
			"was", hint.Hostname, "now", got.Hostname)
	case hint.ID != "" && got.ID != hint.ID:
		p.logf("tunnel replaced behind the same hostname", "hostname", hint.Hostname,
			"was", hint.ID, "now", got.ID)
	}
	return got, nil
}

// probeHint asks the edge, through prober, whether hint is live. A var so a
// test can answer without an edge.
var probeHint = func(ctx context.Context, prober *probe.Prober, hint *Spec, log *slog.Logger) error {
	timed, stop := context.WithTimeout(ctx, probe.Timeout)
	defer stop()
	asked, cancel := context.WithCancelCause(timed)

	err := prober.
		WithID(hint.ID).
		WithHostname(hint.Hostname).
		WithAccountTag(hint.AccountTag).
		WithSecret(hint.Secret).
		WithLogger(zerologger(log)).
		Probe(asked, cancel)

	// The verdict the probe cancels with rather than returns. A hint whose
	// tunnel is gone is not one to vouch for, however alive its hostname is:
	// minting with it replays the record id and gets that name back.
	if err == nil {
		if cause := context.Cause(asked); errors.Is(cause, probe.ErrOrphaned) {
			return cause
		}
	}
	return err
}

func (p *hinted) logf(msg string, args ...any) {
	if p.log != nil {
		p.log.Warn(msg, args...)
	}
}

// hint is what this process already knows about the tunnel, for the mint
// request: the handoff (LIBTUNNEL_SPEC), else the replay mirror
// (LIBTUNNEL_FROM), else the spec From was given; then the field setters over
// the top, each under its LIBTUNNEL__CLOUDFLARE_* mirror — a caller naming a
// field outright means it. Empty when it knows nothing, which mints fresh.
func (b *Backend) hint() (*Spec, error) {
	base := &Spec{}
	if ok, err := v1alpha1.SpecFromEnv(backendName, base); err != nil {
		return nil, err
	} else if !ok {
		if ok, err := v1alpha1.ReplayFromEnv(backendName, base); err != nil {
			return nil, err
		} else if !ok && b.hints != nil {
			*base = *b.hints
		}
	}

	fields := b.fields
	record := fields.RecordID()
	stringEnv(v1.CloudflareRecordIDEnv, &record)
	stringEnv(v1.CloudflareIDEnv, &fields.ID)
	stringEnv(v1.CloudflareNameEnv, &fields.Name)
	stringEnv(v1.CloudflareHostnameEnv, &fields.Hostname)
	stringEnv(v1.CloudflareAccountTagEnv, &fields.AccountTag)
	if v := os.Getenv(v1.CloudflareSecretEnv); v != "" {
		secret, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", v1.CloudflareSecretEnv, err)
		}
		fields.Secret = secret
	}
	if record != "" {
		base.WithMeta(RecordIDKey, record)
	}
	stringField(fields.ID, &base.ID)
	stringField(fields.Name, &base.Name)
	stringField(fields.Hostname, &base.Hostname)
	stringField(fields.AccountTag, &base.AccountTag)
	if len(fields.Secret) > 0 {
		base.Secret = fields.Secret
	}
	return base, nil
}

// mintHeaders resolves the caller's mint request headers: the code headers
// (WithHeader), then v1.CloudflareHeadersEnv, a comma-separated K=V list (env
// beats code). Returns nil when both are empty. Values cannot contain a comma
// or an equals sign — the env form has no escaping.
//
// Spec fields are not among them: the hint rides as its own X-* headers,
// which QuickTunnelProvider sets itself.
func mintHeaders(code http.Header) http.Header {
	var out http.Header

	for key, values := range code {
		if out == nil {
			out = http.Header{}
		}
		out.Del(key)
		for _, v := range values {
			out.Add(key, v)
		}
	}

	raw := os.Getenv(v1.CloudflareHeadersEnv)
	if raw == "" {
		return out
	}
	if out == nil {
		out = http.Header{}
	}
	for _, pair := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if k = strings.TrimSpace(k); !ok || k == "" {
			continue
		}
		out.Set(k, strings.TrimSpace(v))
	}
	return out
}

// providerEndpoint turns a quick-tunnel provider host into a mint endpoint URL:
// https://<host>/tunnel. A value that already carries a scheme is returned
// verbatim, so a full URL (a mock or alternate endpoint) still works.
func providerEndpoint(host string) string {
	if strings.Contains(host, "://") {
		return host
	}
	return "https://" + host + "/tunnel"
}

// bridgeFor is the edge bridge on the same host as the mint endpoint: the
// scheme's WebSocket counterpart, the same host and port, bridgePath. Empty
// when the endpoint is not one.
func bridgeFor(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return ""
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return ""
	}
	u.Path, u.RawQuery, u.Fragment = probe.BridgePath, "", ""
	return u.String()
}

// stringEnv overwrites *field with the env variable's value when it is set
// and non-empty.
func stringEnv(name string, field *string) {
	if v := os.Getenv(name); v != "" {
		*field = v
	}
}

// stringField overwrites *field with override when the override is non-zero.
func stringField(override string, field *string) {
	if override != "" {
		*field = override
	}
}

// CACerts returns the Mozilla CA bundle plus the Cloudflare origin roots —
// the trust set cloudflared uses for its edge TLS connections.
func (b *Backend) CACerts() []*x509.Certificate {
	return trust.Certs()
}

// WithListener dials the Cloudflare edge and proxies it onto l. It blocks
// until the first edge connection is up; the supervisor keeps running in the
// background for the tunnel's lifetime, reporting fatal errors through
// t.Cancel. The origin scheme follows the backend's explicit WithTLS setting
// (default false ⇒ http).
func (b *Backend) WithListener(t *v1alpha1.TunnelImpl[*Spec], l net.Listener) error {
	scheme := "http"
	if b.tls {
		scheme = "https"
	}
	return b.connect(t, &url.URL{Scheme: scheme, Host: l.Addr().String()})
}

// WithLocalURL dials the Cloudflare edge and proxies it onto an
// already-running local origin. The URL arrives validated and reduced to
// scheme+host by the core, so its scheme — not WithTLS — declares how the
// origin is dialed.
func (b *Backend) WithLocalURL(t *v1alpha1.TunnelImpl[*Spec], u *url.URL) error {
	return b.connect(t, u)
}

// connect is the shared engine body behind WithListener and WithLocalURL:
// origin is the one local service the edge proxies to.
func (b *Backend) connect(t *v1alpha1.TunnelImpl[*Spec], origin *url.URL) error {
	if b.envErr != nil {
		return b.envErr
	}
	// cloudflared dials the origin itself: the request reaches it as the edge
	// sent it — the visitor's Host and forwarding headers intact — and an
	// https origin is dialed without verification (noTLSVerify, see
	// ingressFor).
	service := (&url.URL{Scheme: origin.Scheme, Host: origin.Host}).String()
	// Wire runtime state onto the backend: reconnected feeds the supervisor's
	// external-control channel (see NewSupervisor below), edge counts Connected
	// events via the Observer sink, and reconnectCtx is the tunnel context.
	// Once set, b.Reconnect is live.
	b.reconnected = make(chan supervisor.ReconnectSignal)
	b.edge = newEdgeWatcher()
	b.reconnectCtx = t.Context()
	// stopped is the supervisor's to close once it runs; until then a
	// connect that fails closes it on the way out, so Done never waits on
	// an edge that was never held.
	stopped := make(chan struct{})
	b.stopped = stopped
	supervised := false
	defer func() {
		if !supervised {
			close(stopped)
		}
	}()
	// The loop-through's path: random per tunnel, so only this tunnel's own
	// verification requests match the ingress rule that answers them, and
	// every other path goes to the origin.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("loop-through nonce: %w", err)
	}
	loop := loopPrefix + hex.EncodeToString(nonce)
	t.Logger().Info("origin wired", "origin", service)
	ctx := t.Context()
	log := zerologger(t.Logger())
	spec := t.Spec()
	if spec == nil {
		return fmt.Errorf("no spec resolved")
	}
	tunnelID, err := uuid.Parse(spec.ID)
	if err != nil {
		return fmt.Errorf("invalid tunnel id %q in spec: %w", spec.ID, err)
	}

	// quic-go logs a buffer-size warning straight to the global log package
	// (bypassing any configured logger) when the kernel caps its 7 MB UDP
	// buffer request — a throughput note, not an error. Suppress it unless
	// the host explicitly opted in to seeing it.
	if _, set := os.LookupEnv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING"); !set {
		os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	}

	protocol, err := b.resolveEdgeProtocol()
	if err != nil {
		return err
	}
	t.Logger().Info("edge transport selected", "protocol", protocol)

	// The supervisor runs on a context of its own that outlives the tunnel's
	// by up to the grace period. cloudflared's graceful shutdown sends
	// UnregisterConnection on the context it was run with, so a context
	// already canceled cancels the RPC before it leaves, and the edge keeps
	// routing to the closed connection until it notices on its own — ten
	// seconds or so of 502 for the next connector on this tunnel. The tunnel
	// ending closes graceful instead, and run ends when the supervisor has
	// returned, or the grace period is spent waiting for it.
	runCtx, stopRun := context.WithCancel(context.WithoutCancel(ctx))
	graceful := make(chan struct{})

	// The closure scopes the prometheus.DefaultRegisterer swap to supervisor
	// construction: cloudflared registers collectors against the global
	// registerer at construction, which would collide across tunnels and
	// pollute the host application's metrics, so it is pointed at a noop
	// (under promMu) and restored by defer when construction finishes. The
	// supervisor's run and the wait for the first edge connection happen below,
	// outside the lock, so concurrent tunnels neither serialize behind one
	// tunnel's connect nor discard the host's own registrations in the meantime.
	sup, err := func() (*supervisor.Supervisor, error) {
		promMu.Lock()
		defer promMu.Unlock()
		registerer := prometheus.DefaultRegisterer
		prometheus.DefaultRegisterer = noop()
		defer func() { prometheus.DefaultRegisterer = registerer }()

		featureSelector, err := features.NewFeatureSelector(runCtx, spec.AccountTag, nil, false, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create feature selector: %w", err)
		}
		clientConfig, err := client.NewConfig(cloudflaredVersion, fmt.Sprintf("%s_%s", runtime.GOOS, runtime.GOARCH), featureSelector)
		if err != nil {
			return nil, fmt.Errorf("failed to create client config: %w", err)
		}
		protocolSelector, err := connection.NewProtocolSelector("http2", spec.AccountTag, false, edgediscovery.ProtocolPercentage, connection.ResolveTTL, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create protocol selector: %w", err)
		}

		originDialer := ingress.NewOriginDialer(ingress.OriginConfig{}, log)

		prober := b.prober.
			WithID(spec.ID).
			WithHostname(spec.Hostname).
			WithAccountTag(spec.AccountTag).
			WithSecret(spec.Secret).
			WithLogger(log)

		// A tunnel deleted at the edge and a network that dropped look the
		// same from here: cloudflared retries both forever, its backoffs are
		// built retryForever, and the registration error that would say which
		// is discarded before the supervisor can classify it. So the question
		// is asked whenever the tunnel is not fully connected, and only the
		// edge's answer ends it. A healthy tunnel is never probed.
		go func() {
			ticker := time.NewTicker(goneProbeDelay)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// Every connection up is the only state that needs no
					// asking. A deleted tunnel does not drop the connections
					// it already has — the edge gets to them in its own time
					// — but it refuses the next registration at once, so a
					// tunnel short of its full complement is the first thing
					// worth asking about. Probing a partly-connected tunnel
					// is safe: the probe registers on an index the connector
					// never holds.
					if b.edge.liveCount() >= haConnections {
						continue
					}
					timed, stop := context.WithTimeout(ctx, probe.Timeout)
					asked, cancelAsk := context.WithCancelCause(timed)
					err := prober.Probe(asked, cancelAsk)
					if err == nil {
						// Reported by cancellation, not by return: the tunnel
						// is gone and its hostname is not, which ends this
						// tunnel like any other gone verdict — the caller
						// rebuilds on the same name.
						if cause := context.Cause(asked); errors.Is(cause, probe.ErrOrphaned) {
							err = cause
						}
					}
					stop()
					if !errors.Is(err, probe.ErrGone) {
						continue
					}
					t.Logger().Warn("edge disowned the tunnel", "error", err)
					t.Emit(v1.Event{Kind: v1.EventGone})
					t.Cancel(err)
					return
				}
			}
		}()

		// The observer fans connection lifecycle events out to sinks; wire one
		// that feeds edge, so the Reconnect lever can block until the edge is
		// back up and the ErrEdgeUnreachable bound can report how many attempts
		// it took.
		observer := connection.NewObserver(log, log)
		observer.RegisterSink(connection.EventSinkFunc(func(e connection.Event) {
			// Every event, not only the two acted on: this is the only
			// structured view of what the edge is doing, and cloudflared's own
			// account of it is prose in a log line.
			// Only Connected carries a protocol, location and address; the
			// rest leave them zero, and connection.HTTP2 is 0 — logging it
			// unconditionally reports http2 for every event on a QUIC tunnel.
			attrs := []any{"event", edgeEventName(e.EventType), "connIndex", e.Index}
			if e.EventType == connection.Connected {
				attrs = append(attrs, "protocol", e.Protocol.String(),
					"location", e.Location, "edgeAddress", e.EdgeAddress)
			}
			if e.URL != "" {
				attrs = append(attrs, "url", e.URL)
			}
			t.Logger().Debug("edge event", attrs...)
			switch e.EventType {
			case connection.Connected:
				// The first live connection — at startup, or after every
				// one had dropped — is when routing has to be verified
				// again: the edge may be fanning a new location out. Every
				// connection up is the tunnel's news; one of several
				// registering is neither.
				alive, full := b.edge.up(e.Index)
				if alive && b.establishing.CompareAndSwap(false, true) {
					go func() {
						defer b.establishing.Store(false)
						b.establish(ctx, t, loopThroughClient(prober), "https://"+spec.GetHostname()+loop, t.Logger())
					}()
				}
				if full {
					t.Emit(v1.Event{Kind: v1.EventConnected})
				}
			case connection.Reconnecting:
				b.edge.attempt(e.Index)
			case connection.Disconnected:
				// The last connection going is the tunnel's news; one of
				// several is not, and neither is a serve attempt ending that
				// never registered — which is most of what the supervisor
				// reports here during an outage.
				if b.edge.disconnect(e.Index) {
					t.Emit(v1.Event{Kind: v1.EventDisconnected})
				}
			}
		}))

		tunnelConfig := &supervisor.TunnelConfig{
			ClientConfig: clientConfig,
			// cloudflared's own default (its --grace-period flag): how long the
			// supervisor waits for in-flight requests on graceful shutdown — and
			// ctx.Done is wired as the graceful-shutdown signal below, so this
			// bounds teardown after a cancel. Max accepted is 3m.
			GracePeriod: gracePeriod,
			Region:      "",
			// Nil on a network that carries 7844, and cloudflared discovers
			// the edge by SRV with its own DoT fallback. Where it does not,
			// the prober hands back a forwarder to the bridge it just reached
			// the edge through — the supervisor would otherwise retry
			// addresses this network drops, forever.
			EdgeAddrs:     prober.EdgeAddrs(ctx),
			EdgeIPVersion: allregions.Auto,
			HAConnections: haConnections,
			// No tags, matching cloudflared's quick-tunnel default. (Tags never
			// were the connector ID — client.NewConfig mints a fresh random UUID
			// for that; tags only become Cf-Warp-Tag-* headers injected into
			// every request hitting the origin.)
			Tags:            nil,
			Log:             log,
			LogTransport:    log,
			Observer:        observer,
			ReportedVersion: cloudflaredVersion,
			Retries:         5,
			RunFromTerminal: false,
			NamedTunnel: &connection.TunnelProperties{
				Credentials: connection.Credentials{
					AccountTag:   spec.AccountTag,
					TunnelSecret: spec.Secret,
					TunnelID:     tunnelID,
				},
				QuickTunnelUrl: t.Hostname(),
			},
			ProtocolSelector:   protocolSelector,
			EdgeTLSConfigs:     prober.TLSConfigs(),
			MaxEdgeAddrRetries: 8,
			RPCTimeout:         5 * time.Second,
			// Static, at cloudflared's own default: the service only serves
			// its DNS origin, which nothing here uses, and the refresh loop
			// the non-static one runs races with itself — its resolver's Dial
			// hook writes one field from the parallel A and AAAA lookups.
			OriginDNSService:    origins.NewStaticDNSResolverService([]netip.AddrPort{originDNSResolver}, originDialer, log, noop()),
			OriginDialerService: originDialer,
		}

		internalRules := []ingress.Rule{}
		parsed, err := ingressFor(service, loop, b.http2)
		if err != nil {
			return nil, err
		}
		orchestrator, err := orchestration.NewOrchestrator(runCtx, &orchestration.Config{
			Ingress:             &parsed,
			WarpRouting:         ingress.NewWarpRoutingConfig(&config.WarpRoutingConfig{}), // cloudflared defaults: 5s connect, unlimited flows, 30s keepalive
			OriginDialerService: originDialer,
			ConfigurationFlags:  map[string]string{}, // CLI-flag overrides for remote config; empty matches cloudflared quick-tunnel behavior
		}, tunnelConfig.Tags, internalRules, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create orchestrator: %w", err)
		}

		// b.reconnected is the backend's external-control channel, wired above;
		// here it is handed to the supervisor, which selects on it. b.Reconnect
		// sends on it to cycle the edge.
		sup, err := supervisor.NewSupervisor(tunnelConfig, orchestrator, b.reconnected, graceful)
		if err != nil {
			return nil, fmt.Errorf("failed to create supervisor: %w", err)
		}
		return sup, nil
	}()
	if err != nil {
		stopRun()
		return err
	}

	connected := signal.New(make(chan struct{}))
	supervised = true
	go func() {
		defer close(stopped)
		defer stopRun()
		if err := sup.Run(runCtx, connected); err != nil {
			t.Cancel(fmt.Errorf("supervisor run failed: %w", err))
		}
	}()
	go func() {
		<-ctx.Done()
		close(graceful)
		select {
		case <-stopped:
		case <-time.After(gracePeriod):
			t.Logger().Warn("edge connections still open after the grace period, closing them", "grace", gracePeriod)
			stopRun()
		}
	}()

	// The bound on the first edge connection, read off the class that reports
	// it — see v1.ErrEdgeUnreachable for why thirty seconds and why only the
	// first connection.
	edgeBudget := v1.Budget(v1.ErrEdgeUnreachable)
	timeout := time.NewTimer(edgeBudget)
	defer timeout.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connected.Wait():
	case <-timeout.C:
		return fmt.Errorf("%w: no connection after %d attempts (%d ended) in %s: %s",
			v1.ErrEdgeUnreachable, b.edge.attemptCount(), b.edge.disconnectCount(), edgeBudget, edgeBlockedHint)
	}
	return nil
}

// ingressFor is cloudflared's ingress for one origin: the loop-through path
// answered 204 by cloudflared itself, so the origin never sees the tunnel's
// own verification, and every other request sent to service. HTTP/2 to the
// origin follows WithHTTP2; the service's scheme picks http or https, and TLS
// verification is off — a local origin may carry a self-signed cert.
func ingressFor(service, loop string, http2 bool) (ingress.Ingress, error) {
	noTLSVerify := true
	parsed, err := ingress.ParseIngress(&config.Configuration{
		OriginRequest: config.OriginRequestConfig{
			NoTLSVerify: &noTLSVerify,
			Http2Origin: &http2,
		},
		WarpRouting: config.WarpRoutingConfig{},
		Ingress: []config.UnvalidatedIngressRule{
			{Path: "^" + regexp.QuoteMeta(loop) + "$", Service: "http_status:204"},
			{Service: service},
		},
	})
	if err != nil {
		return ingress.Ingress{}, fmt.Errorf("failed to parse ingress for %s: %w", service, err)
	}
	return parsed, nil
}

// loopThroughClient is the client the verification goes out on. It resolves
// through the prober's DoH resolvers and dials the address itself, so the
// machine's resolver is never asked: this is the first request for the name
// from this host, and a resolver asked a beat early caches the NXDOMAIN for
// the zone's SOA.
func loopThroughClient(p *probe.Prober) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: trust.Pool()},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ip, err := p.LookupHost(ctx, host)
				if err != nil {
					return nil, err
				}
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
		},
	}
}

// establish sends the loop-through to url until this tunnel's cloudflared
// answers it, then reports EventEstablished. It has no bound of its own: a
// caller that wants one puts it on the tunnel's context.
func (b *Backend) establish(ctx context.Context, t emitter, client *http.Client, url string, log *slog.Logger) {
	start := time.Now()
	attempts := 0
	for {
		attempts++
		err := verify(ctx, client, url)
		if err == nil {
			log.Info("tunnel established", "url", url, "attempts", attempts, "after", time.Since(start).Round(time.Millisecond))
			t.Emit(v1.Event{Kind: v1.EventEstablished})
			return
		}
		// Every attempt, because the tunnel is up and serving nothing until
		// one of these succeeds, and the caller's only other signal is a URL
		// that never arrives.
		log.Debug("tunnel not established yet", "url", url, "attempt", attempts, "error", err)

		select {
		case <-ctx.Done():
			log.Warn("tunnel never established", "url", url, "attempts", attempts,
				"after", time.Since(start).Round(time.Millisecond), "error", err)
			return
		case <-time.After(b.establishInterval):
		}
	}
}

// verify makes one loop-through and reports whether this tunnel's
// cloudflared answered it — a 204 on the tunnel's own path, which only its
// ingress answers — rather than the edge answering in its place.
func verify(ctx context.Context, client *http.Client, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		// The edge answering for a route it has not finished wiring looks
		// exactly like this — 530 or 1033 while the record points at a
		// tunnel the colo does not know yet.
		return fmt.Errorf("answered %s, want %d", resp.Status, http.StatusNoContent)
	}
	return nil
}

// The loop-through that verifies the public URL. Every establishInterval a
// request goes to a path only this tunnel's ingress knows (loopPrefix plus a
// random nonce); cloudflared answers it 204 itself, so the origin never sees
// it. Until the edge has fanned the tunnel's location out to its colos it
// answers 530 in cloudflared's place, and the loop tries again.
//
// A var, not a const, so a test can shorten it rather than sleep through it
// — captured on the Backend at construction.
var establishInterval = 1 * time.Second

// loopPrefix starts the loop-through's path.
const loopPrefix = "/.well-known/libtunnel/"

// emitter is the half of the tunnel the probe needs: somewhere to report.
type emitter interface{ Emit(v1.Event) }

// edgeBlockedHint is cloudflared's own diagnosis of this failure, which it logs
// at warn level from selectNextProtocol. Repeated verbatim so the error carries
// the same guidance without the caller having to correlate it with a log line.
//
// It rides only the timeout branch. A credential the edge refuses leaves
// through its own case above, so reaching this means nothing better is known
// about why the edge never answered.
const edgeBlockedHint = "your machine/network is getting its egress to the tunnel edge " +
	"blocked or dropped. Make sure to allow egress connectivity as per " +
	"https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/configuration/ports-and-ips/ " +
	"(WithEdgeProtocol pins the transport when only one of UDP or TCP is allowed)"

// noopImpl satisfies the metrics interfaces cloudflared insists on with
// do-nothing implementations.
type noopImpl struct {
	origins.Metrics
	prometheus.Registerer
}

var (
	_ origins.Metrics       = (*noopImpl)(nil)
	_ prometheus.Registerer = (*noopImpl)(nil)
)

func noop() *noopImpl {
	return &noopImpl{}
}

func (n *noopImpl) IncrementDNSTCPRequests() {}
func (n *noopImpl) IncrementDNSUDPRequests() {}

func (n *noopImpl) Register(prometheus.Collector) error  { return nil }
func (n *noopImpl) MustRegister(...prometheus.Collector) {}
func (n *noopImpl) Unregister(prometheus.Collector) bool { return true }
