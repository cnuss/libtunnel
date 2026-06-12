package e2e

// Shared plumbing for the scenario tests: re-exec roles, live gating, retry
// helpers, and a self-signed TLS config. Scenario tests re-exec this test
// binary with -test.run anchored to themselves and a role variable set; the
// role branch at the top of each test turns the process into the child.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/cnuss/libtunnel"
	v1 "github.com/cnuss/libtunnel/v1"
	"github.com/cnuss/libtunnel/v1alpha1/cloudflare"
)

// roleEnv selects a child role inside a re-exec'd test binary.
const roleEnv = "LIBTUNNEL_E2E_ROLE"

func role() string { return os.Getenv(roleEnv) }

// reexec builds a command that re-runs this test binary anchored to a single
// test, with extra environment entries appended to the current environment.
func reexec(test string, extraEnv ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.v")
	cmd.Env = append(os.Environ(), extraEnv...)
	return cmd
}

// gateLive skips the test unless the live tier is enabled, fails fast when
// the preflight comms check failed, scrubs any inherited TUNNEL_SPEC so live
// scenarios always mint their own, and paces the suite.
func gateLive(t *testing.T) {
	t.Helper()
	if os.Getenv("LIBTUNNEL_E2E_LIVE") != "1" {
		t.Skip("live scenario (mints a real quick tunnel); set LIBTUNNEL_E2E_LIVE=1 to run")
	}
	if err := preflight(); err != nil {
		t.Fatalf("live preflight failed (skipping the expensive part): %v", err)
	}
	t.Setenv(libtunnel.SpecEnv, "")
	paceLive()
}

// preflight is the basic-comms check the whole live tier hangs off: one
// quick-tunnel mint with a short budget. If it fails (rate limit, no
// network), every live test fails fast instead of each burning its own
// timeout. The minted spec is not wasted — TestLiveTunnel adopts it through
// the environment instead of minting again.
var (
	preflightOnce sync.Once
	preflightErr  error
	preflightSpec *v1.CloudflareSpec
)

func preflight() error {
	preflightOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		preflightSpec, preflightErr = cloudflare.QuickTunnel().Spec(ctx)
		lastLiveStart = time.Now() // the mint counts toward pacing
	})
	return preflightErr
}

// lastLiveStart paces back-to-back live tests. The quick-tunnel API and edge
// provisioning are burst-sensitive: minting a dozen tunnels in a few minutes
// drew 429s and route-propagation failures live, while the same tests pass
// individually. Tests run sequentially (no t.Parallel), so a plain variable
// suffices.
var lastLiveStart time.Time

func paceLive() {
	const gap = 20 * time.Second
	if since := time.Since(lastLiveStart); since < gap {
		time.Sleep(gap - since)
	}
	lastLiveStart = time.Now()
}

// waitReady waits for TunnelReady with a deadline. A tunnel that fails
// internally (rate-limited mint, dead supervisor) never closes TunnelReady,
// so an unbounded wait would hang the whole suite.
func waitReady(t *testing.T, ready <-chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(d):
		t.Fatalf("tunnel not ready after %v (rate-limited mint or dead connection?)", d)
	}
}

// getBody requests url once and returns the body.
func getBody(url string) (string, int, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

// eventuallyBody polls url until the body equals want or the deadline
// expires. Fresh tunnels and just-restarted origins can lag a few seconds
// behind the edge.
func eventuallyBody(t *testing.T, url, want string, deadline time.Duration) {
	t.Helper()
	var last string
	var lastErr error
	for end := time.Now().Add(deadline); time.Now().Before(end); {
		body, code, err := getBody(url)
		last, lastErr = body, err
		if err == nil && code == http.StatusOK && body == want {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("never saw body %q from %s (last body %q, last err %v)", want, url, last, lastErr)
}

// selfSignedTLS returns a TLS config with a fresh self-signed certificate for
// 127.0.0.1.
func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "libtunnel e2e"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// serveBody serves a fixed body on l in the background. The returned server
// handle matters when a scenario needs the origin actually dead: Close tears
// down established (kept-alive) connections too, which closing the bare
// listener does not — pooled origin connections would keep serving.
func serveBody(l net.Listener, body string) *http.Server {
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	})}
	go srv.Serve(l)
	return srv
}
