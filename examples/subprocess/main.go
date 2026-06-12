// Command subprocess is the canonical parent→child spec handoff: the parent
// process mints a tunnel spec and passes it to a spawned child through the
// TUNNEL_SPEC environment variable; the child provides the listener, connects
// the tunnel, and serves; the parent then requests the child's public URL.
//
// It needs network access (it mints a tunnel from api.trycloudflare.com); the
// e2e harness only runs it when LIBTUNNEL_E2E_LIVE=1.
package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/cnuss/libtunnel"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		child()
		return
	}
	parent()
}

// parent mints a spec (without ever connecting), hands it to a spawned child
// through the environment, and requests the child's public URL once the
// child reports the tunnel ready.
func parent() {
	t := libtunnel.New(libtunnel.Cloudflare())
	spec := t.Spec()
	fmt.Printf("minted: %s\n", spec.Hostname)

	entry, err := libtunnel.SpecEnviron(spec)
	if err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "child")
	cmd.Env = append(os.Environ(), entry)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	defer cmd.Process.Kill()

	// The child prints "ready: <url>" once the tunnel is reachable.
	var childURL string
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Printf("child: %s\n", line)
		if u, ok := strings.CutPrefix(line, "ready: "); ok {
			childURL = u
			break
		}
	}
	if childURL == "" {
		log.Fatal("child exited before the tunnel became ready")
	}

	// Both processes share the tunnel identity: the parent can reach the
	// child through the hostname it minted itself.
	resp, err := http.Get("https://" + spec.Hostname + "/")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("handoff: %s\n", body)
}

// child adopts the spec from the environment (the Cloudflare credential
// chain finds TUNNEL_SPEC before minting anything), provides the listener,
// and serves until the parent kills it.
func child() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}

	conn := libtunnel.New(libtunnel.Cloudflare()).WithListener(l)

	go func() {
		err := http.Serve(conn.Listener(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello from the child")
		}))
		log.Fatal(err)
	}()

	<-conn.TunnelReady()
	fmt.Printf("ready: %s\n", conn.URL())

	select {} // serve until the parent kills us
}
