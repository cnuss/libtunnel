package cloudflare

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"github.com/rs/zerolog"
)

// slogWriter adapts zerolog's io.Writer sink onto slog so cloudflared tunnel
// logs surface through the tunnel's configured logger instead of being
// discarded. zerolog accepts any io.Writer; slog has no matching ingress
// writer, so forward each emitted line as a debug record.
type slogWriter struct {
	log *slog.Logger
}

var _ io.Writer = slogWriter{}

func (w slogWriter) Write(p []byte) (int, error) {
	w.log.Debug(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// zerologger bridges the tunnel's slog.Logger into the *zerolog.Logger
// cloudflared's plumbing requires. When the handler won't accept debug
// records (the silent default), it returns a disabled logger so cloudflared's
// per-event JSON serialization is skipped instead of encoded and discarded —
// this sits on the proxy hot path.
func zerologger(log *slog.Logger) *zerolog.Logger {
	if !log.Enabled(context.Background(), slog.LevelDebug) {
		l := zerolog.Nop()
		return &l
	}
	l := zerolog.New(slogWriter{log: log}).With().Str("component", "tunnel").Logger()
	return &l
}
