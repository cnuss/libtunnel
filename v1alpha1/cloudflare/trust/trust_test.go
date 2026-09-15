package trust

import (
	"crypto/x509"
	"testing"
)

// TestPoolCarriesEmbeddedRoots pins that the pool libtunnel dials with
// contains the roots compiled into the binary, so a host with no
// ca-certificates package can still verify the mint and edge endpoints. Every
// embedded root is self-signed, so verifying one against the pool proves it
// is in there without reaching the network.
func TestPoolCarriesEmbeddedRoots(t *testing.T) {
	pool := Pool()
	if pool == nil {
		t.Fatal("Pool() = nil")
	}
	embedded := Certs()
	if len(embedded) == 0 {
		t.Fatal("no embedded roots parsed")
	}
	for _, root := range embedded {
		if _, err := root.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Fatalf("embedded root %q not in the pool: %v", root.Subject.CommonName, err)
		}
	}
}
