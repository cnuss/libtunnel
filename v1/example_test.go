package v1_test

// go vet rejects Example funcs bound to parameterized types (ExampleTunnel_*
// — its example checker hasn't caught up with generics), so the examples here
// use package-level names instead.

import (
	"fmt"
	"net"
	"net/http"

	"github.com/cnuss/libtunnel"
	v1 "github.com/cnuss/libtunnel/v1"
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

	<-conn.TunnelReady()
	fmt.Println(conn.URL()) // https://<something>.trycloudflare.com/
}

// A spec round-trips through the environment: the parent exports it, the
// child adopts it. This is the TUNNEL_SPEC parent→child handoff.
func Example_handoff() {
	parent := &v1.CloudflareSpec{Hostname: "demo.trycloudflare.com"}
	if err := libtunnel.ExportSpec(parent); err != nil {
		panic(err)
	}

	child := &v1.CloudflareSpec{}
	ok, err := libtunnel.SpecFromEnv(child)
	if err != nil {
		panic(err)
	}

	fmt.Printf("adopted=%t hostname=%s\n", ok, child.Hostname)
	// Output: adopted=true hostname=demo.trycloudflare.com
}

// Getters resolve lazily from the backend's credential chain — here a spec
// adopted from the environment, so nothing touches the network.
func Example_lazy() {
	spec := &v1.CloudflareSpec{Hostname: "demo.trycloudflare.com"}
	if err := libtunnel.ExportSpec(spec); err != nil {
		panic(err)
	}

	t := libtunnel.New(libtunnel.Cloudflare())
	fmt.Printf("%s . %s : %d\n", t.Host(), t.Domain(), t.Port())
	// Output: demo . trycloudflare.com : 443
}
