package v1_test

// go vet rejects Example funcs bound to parameterized types (ExampleTunnel_*
// — its example checker hasn't caught up with generics), so the examples here
// use package-level names instead.

import (
	"fmt"
	"net"
	"net/http"
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
		fmt.Println(conn.URL()) // https://<something>.trycloudflare.com/
	case <-conn.Done():
		fmt.Println(conn.Err())
	}
}

// LIBTUNNEL_SPEC is the parent→child handoff channel: a parent process that
// mints a tunnel exports its spec there automatically, and a child's
// Cloudflare credential chain adopts it at construction — no API to call.
// Here the environment is populated by hand to stand in for the parent.
func Example_handoff() {
	os.Setenv("LIBTUNNEL_SPEC", `{"backend":"cloudflare","spec":{"hostname":"demo.trycloudflare.com"}}`)
	defer os.Unsetenv("LIBTUNNEL_SPEC")

	t := libtunnel.New(libtunnel.Cloudflare())
	fmt.Println(t.Hostname())
	// Output: demo.trycloudflare.com
}

// Getters resolve lazily from the backend's credential chain — here a spec
// adopted from the environment, so nothing touches the network.
func Example_lazy() {
	os.Setenv("LIBTUNNEL_SPEC", `{"backend":"cloudflare","spec":{"hostname":"demo.trycloudflare.com"}}`)
	defer os.Unsetenv("LIBTUNNEL_SPEC")

	t := libtunnel.New(libtunnel.Cloudflare())
	fmt.Printf("%s . %s : %d\n", t.Host(), t.Domain(), t.Port())
	// Output: demo . trycloudflare.com : 443
}
