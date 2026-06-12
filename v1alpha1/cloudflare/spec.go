package cloudflare

import v1 "github.com/cnuss/libtunnel/v1"

// Spec is the Cloudflare backend's credential set — the spec type T produced
// by libtunnel.Cloudflare(). The json tags match the api.trycloudflare.com
// response and the TUNNEL_SPEC handoff encoding.
type Spec struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Hostname   string `json:"hostname"`
	AccountTag string `json:"account_tag"`
	Secret     []byte `json:"secret"`
}

var _ v1.Spec = (*Spec)(nil)

// GetHostname implements v1.Spec.
func (s *Spec) GetHostname() string {
	if s == nil {
		return ""
	}
	return s.Hostname
}
