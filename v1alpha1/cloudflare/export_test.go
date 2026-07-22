package cloudflare

import "time"

// Test-only accessors for the env-fixed backend knobs: the fields are
// implementation detail, but the env-fixing behavior is contract and needs
// pinning from the external test package.

func (b *Backend) TLS() bool                     { return b.tls }
func (b *Backend) HTTP2() bool                   { return b.http2 }
func (b *Backend) EnvErr() error                 { return b.envErr }
func (b *Backend) FlushInterval() *time.Duration { return b.chopInterval }
func (b *Backend) Padding() bool                 { return b.padding }
