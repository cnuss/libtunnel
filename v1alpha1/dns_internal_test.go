package v1alpha1

import "testing"

// TestDNSName pins the port-stripping the readiness poller depends on: the v1
// contract allows GetHostname to carry host:port, but DNS queries take bare
// names.
func TestDNSName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"app.example.com", "app.example.com"},
		{"app.example.com:8443", "app.example.com"},
		{"example.com:8443", "example.com"},
		{"demo.trycloudflare.com", "demo.trycloudflare.com"},
		{"localhost:8080", "localhost"},
	}
	for _, c := range cases {
		if got := dnsName(c.in); got != c.want {
			t.Errorf("dnsName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
