// Package trust is the trust set for the connections libtunnel makes on its
// own behalf: the mint, the edge, the DoH resolvers, the loop-through.
package trust

import (
	"crypto/x509"
	"encoding/pem"
	"sync"

	"github.com/breml/rootcerts/embedded"
	"github.com/cloudflare/cloudflared/tlsconfig"
)

// Certs is the roots compiled into the binary, parsed once per process: the
// Mozilla bundle is a compile-time constant and the Cloudflare roots are
// fixed, so re-parsing ~150 certificates per tunnel was pure waste.
var Certs = sync.OnceValue(func() []*x509.Certificate {
	certificates := []*x509.Certificate{}

	rest := []byte(embedded.MozillaCACertificatesPEM())
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remainder
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certificates = append(certificates, cert)
		}
	}

	cloudflareRoots, _ := tlsconfig.GetCloudflareRootCA()
	return append(certificates, cloudflareRoots...)
})

// Pool is the host's store when it has one, plus Certs on top — so a
// scratch, busybox or distroless-without-certs image mints and connects
// without anyone installing ca-certificates first. A host with no store is
// not an error: SystemCertPool yields an empty pool there, and the embedded
// roots go on top either way, which is the point.
var Pool = sync.OnceValue(func() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	for _, c := range Certs() {
		pool.AddCert(c)
	}
	return pool
})
