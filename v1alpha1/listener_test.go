package v1alpha1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// declaredListener opts in to TLS detection through the probe interface.
type declaredListener struct {
	net.Listener
	tls bool
}

func (d declaredListener) TLS() bool { return d.tls }

func TestIsTLS(t *testing.T) {
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()

	if IsTLS(plain) {
		t.Error("IsTLS(net.Listen) = true, want false")
	}

	wrapped := tls.NewListener(plain, selfSigned(t))
	if !IsTLS(wrapped) {
		t.Error("IsTLS(tls.NewListener) = false, want true")
	}

	if !IsTLS(declaredListener{Listener: plain, tls: true}) {
		t.Error("isTLS ignored a listener declaring TLS() = true")
	}
	if IsTLS(declaredListener{Listener: wrapped, tls: false}) {
		t.Error("isTLS ignored a listener declaring TLS() = false")
	}
}

// selfSigned returns a minimal TLS config so tls.NewListener succeeds.
func selfSigned(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
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
