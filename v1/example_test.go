package v1_test

// go vet rejects Example funcs bound to parameterized types (ExampleTunnel_*
// — its example checker hasn't caught up with generics), so the examples here
// use package-level names instead.

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/cnuss/libtunnel"
)

// The full lifecycle: bind a listener, hand it to the tunnel (which lazily
// starts the edge connection), serve on it, and wait until the tunnel is
// publicly reachable. Not run as a test — it mints a real quick tunnel.
func Example() {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	conn := libtunnel.New(libtunnel.Cloudflare()).WithListener(l)

	go http.Serve(conn.Listener(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))

	select {
	case <-conn.TunnelReady():
		fmt.Println(conn.URL()) // https://<something>.tunneled.pizza/
	case <-conn.Done():
		fmt.Println(conn.Err())
	}
}

// stubProvider stands in for tunnel.pizza: a mint endpoint that hands back
// the hostname it was hinted, the way the real one does while the
// reservation holds. It is pointed at through the same variable an operator
// would use for an alternate provider.
func stubProvider() (stop func()) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"success":true,"result":{"hostname":%q}}`, r.Header.Get("X-Hostname"))
	}))
	os.Setenv("LIBTUNNEL__CLOUDFLARE_PROVIDER", srv.URL)
	return func() {
		os.Unsetenv("LIBTUNNEL__CLOUDFLARE_PROVIDER")
		srv.Close()
	}
}

// LIBTUNNEL_SPEC is the parent→child handoff channel: a parent process that
// mints a tunnel exports its spec there automatically, and a child's
// Cloudflare credential chain sends it to the provider as the hint for its
// own mint, so the provider hands the same tunnel back. Here the environment
// is populated by hand to stand in for the parent.
func Example_handoff() {
	defer stubProvider()()
	os.Setenv("LIBTUNNEL_SPEC", `{"backend":"cloudflare","spec":{"hostname":"demo.tunneled.pizza"}}`)
	defer os.Unsetenv("LIBTUNNEL_SPEC")

	t := libtunnel.New(libtunnel.Cloudflare())
	fmt.Println(t.Hostname())
	// Output: demo.tunneled.pizza
}

// Getters resolve lazily from the backend's credential chain — nothing is
// fetched until the first one is read.
func Example_lazy() {
	defer stubProvider()()
	os.Setenv("LIBTUNNEL_SPEC", `{"backend":"cloudflare","spec":{"hostname":"demo.tunneled.pizza"}}`)
	defer os.Unsetenv("LIBTUNNEL_SPEC")

	t := libtunnel.New(libtunnel.Cloudflare())
	fmt.Printf("%s . %s : %d\n", t.Host(), t.Domain(), t.Port())
	// Output: demo . tunneled.pizza : 443
}
