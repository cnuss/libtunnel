// Command offline demonstrates the spec handoff and the lazy getters without
// any network access: a spec is exported into the environment (as a parent
// process would), then a tunnel built with the Env provider adopts it instead
// of minting a fresh quick tunnel.
package main

import (
	"fmt"
	"log"

	"github.com/cnuss/libtunnel"
	v1 "github.com/cnuss/libtunnel/v1"
)

func main() {
	// The parent side of a handoff: mint (here: fabricate) a spec and export
	// it. A child process inherits TUNNEL_SPEC through its environment.
	spec := &v1.CloudflareSpec{
		ID:       "00000000-0000-0000-0000-000000000000",
		Name:     "offline-demo",
		Hostname: "demo.trycloudflare.com",
	}
	if err := libtunnel.ExportSpec(spec); err != nil {
		log.Fatal(err)
	}

	// The child side: the Env provider finds TUNNEL_SPEC and adopts it — the
	// wrapped QuickTunnel provider is never consulted, so no network happens.
	t := libtunnel.New(libtunnel.Cloudflare(), libtunnel.Env(libtunnel.QuickTunnel()))

	fmt.Printf("hostname: %s\n", t.Hostname())
	fmt.Printf("host: %s\n", t.Host())
	fmt.Printf("domain: %s\n", t.Domain())
	fmt.Printf("port: %d\n", t.Port())
	fmt.Printf("ca certs: %t\n", len(t.CACerts()) > 0)
}
