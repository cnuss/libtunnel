// Command serve exposes a local HTTPS server to the public internet through
// a Cloudflare quick tunnel, waits until the tunnel is reachable end to end,
// then requests its own public URL to prove the round trip.
//
// It needs network access (it mints a tunnel from api.trycloudflare.com); the
// e2e harness only runs it when LIBTUNNEL_E2E_LIVE=1.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/cnuss/libtunnel"
)

func main() {
	// The tunnel's ingress dials the origin over https (certificate
	// verification disabled), so the local listener must speak TLS — a
	// self-signed certificate is enough.
	l, err := tls.Listen("tcp", "127.0.0.1:0", selfSigned())
	if err != nil {
		log.Fatal(err)
	}

	conn := libtunnel.New(libtunnel.Cloudflare(), libtunnel.QuickTunnel()).WithListener(l)

	go func() {
		err := http.Serve(conn.Listener(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello from libtunnel")
		}))
		log.Fatal(err)
	}()

	fmt.Printf("local: %s\n", conn.LocalURL())
	<-conn.TunnelReady()
	fmt.Printf("public: %s\n", conn.URL())

	resp, err := http.Get(conn.URL().String())
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("served: %s\n", body)
}

// selfSigned returns a TLS config with a fresh self-signed certificate for
// 127.0.0.1 — the minimum the tunnel's https ingress needs from the origin.
func selfSigned() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "libtunnel example"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
	}
}
