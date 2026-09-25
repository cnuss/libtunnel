package probe

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// bridgeServer is the bridge the way tunnel.pizza runs it: a WebSocket on
// /relay whose frames are piped, unread, to upstream. Plain ws, so the test
// needs no certificate; the scheme is the only difference from the real one.
func bridgeServer(t *testing.T, upstream string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != BridgePath {
			http.NotFound(w, r)
			return
		}
		websocket.Server{
			Handshake: func(*websocket.Config, *http.Request) error { return nil },
			Handler: func(ws *websocket.Conn) {
				defer ws.Close()
				ws.PayloadType = websocket.BinaryFrame
				remote, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer remote.Close()
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(remote, ws); done <- struct{}{} }()
				go func() { _, _ = io.Copy(ws, remote); done <- struct{}{} }()
				<-done
			},
		}.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return "ws://" + srv.Listener.Addr().String() + BridgePath
}

// roundTrip proves bytes cross conn both ways, against an echo at the far end.
func roundTrip(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("through the bridge")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len("through the bridge"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "through the bridge" {
		t.Errorf("echoed %q", got)
	}
}

// TestDialBridgeCarriesBytes pins the route itself: what is written to the
// stream dialBridge returns comes out of the bridge's upstream, and what the
// upstream answers comes back — a TLS session to the edge can ride it.
func TestDialBridgeCarriesBytes(t *testing.T) {
	bridge := bridgeServer(t, echoServer(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := New().WithBridge(bridge).dialBridge(ctx)
	if err != nil {
		t.Fatalf("dialBridge: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn)
}

// TestDialBridgeThroughTheProxy pins that the bridge is reached the way a
// locked-down network requires: CONNECT to the bridge's host through the
// proxy the environment names, and the upgrade inside that.
func TestDialBridgeThroughTheProxy(t *testing.T) {
	bridge := bridgeServer(t, echoServer(t))
	proxy := &connectProxy{}
	proxy.start(t)
	// The bridge is on loopback, which no proxy setting ever covers, so the
	// proxy is handed over directly rather than through the environment.
	p := New().WithBridge(bridge)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	target := p.bridges[0].Host
	raw, err := dialViaProxy(ctx, &url.URL{Scheme: "http", Host: proxy.addr}, target)
	if err != nil {
		t.Fatalf("dialViaProxy: %v", err)
	}
	config, err := websocket.NewConfig(bridge, "http://"+p.bridges[0].Hostname()+"/")
	if err != nil {
		t.Fatal(err)
	}
	ws, err := websocket.NewClient(config, raw)
	if err != nil {
		t.Fatalf("upgrade through the proxy: %v", err)
	}
	defer ws.Close()
	ws.PayloadType = websocket.BinaryFrame
	roundTrip(t, ws)
}

// TestWithBridgeTakesOnlyAWebSocketURL pins the knob: a ws or wss URL with a
// host is the bridge, anything else leaves the default in place — a prober
// built on its own still has a way past a network that drops 7844.
func TestWithBridgeTakesOnlyAWebSocketURL(t *testing.T) {
	if got := New().Bridge(); got != DefaultBridge {
		t.Errorf("New().Bridge() = %q, want DefaultBridge", got)
	}
	for _, tc := range []struct{ in, want string }{
		{"wss://bridge.example/relay", "wss://bridge.example/relay"},
		{"ws://localhost:3000/relay", "ws://localhost:3000/relay"},
		{"https://tunnel.pizza/relay", DefaultBridge},
		{"", DefaultBridge},
		{"wss:///relay", DefaultBridge},
	} {
		if got := New().WithBridge(tc.in).Bridge(); got != tc.want {
			t.Errorf("WithBridge(%q).Bridge() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRoutesStartWhereTheLastAskEnded pins the memo: the route that answered
// goes first next time, every route is still tried, the bridge is only a
// route once named, and the edge's own addresses need no remembering.
func TestRoutesStartWhereTheLastAskEnded(t *testing.T) {
	p := New()
	if got := p.routes(); !slices.Equal(got, []route{routeDirect, routeBridge}) {
		t.Errorf("routes = %v, want direct, bridge", got)
	}
	p.remember(routeBridge)
	if got := p.routes(); !slices.Equal(got, []route{routeBridge, routeDirect}) {
		t.Errorf("routes after the bridge answered = %v, want it first", got)
	}
	p.remember(routeDirect)
	if got := p.routes(); !slices.Equal(got, []route{routeDirect, routeBridge}) {
		t.Errorf("routes after the edge answered = %v, want the default order", got)
	}
}

// TestForwardCarriesTheBridge pins how the supervisor gets the bridge: a
// loopback address it dials as if it were the edge, with each connection
// carried on through the WebSocket.
func TestForwardCarriesTheBridge(t *testing.T) {
	p := New().WithBridge(bridgeServer(t, echoServer(t)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	local, err := p.forward(ctx, routeBridge, p.dialBridge)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	conn, err := net.DialTimeout("tcp", local, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the forwarder: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn)
}

// TestDialBridgeFallsBackToTheDefault pins the order: the bridge on the
// provider's host first, tunnel.pizza's when that one does not answer — a
// provider with no bridge of its own still gets the edge through the one
// that exists. The named bridge here refuses the upgrade; the fallback is
// stood in for by a second test bridge, so nothing real is dialed.
func TestDialBridgeFallsBackToTheDefault(t *testing.T) {
	refusing := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(refusing.Close)
	p := New().WithBridge("ws://" + refusing.Listener.Addr().String() + BridgePath)
	fallback, _ := url.Parse(bridgeServer(t, echoServer(t)))
	p.bridges[1] = fallback

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := p.dialBridge(ctx)
	if err != nil {
		t.Fatalf("dialBridge: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn)
}
