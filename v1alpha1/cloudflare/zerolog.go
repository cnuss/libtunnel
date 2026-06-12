package cloudflare

import (
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

func (w slogWriter) Write(p []byte) (int, error) {
	w.log.Debug(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// zerologger bridges the tunnel's slog.Logger into the *zerolog.Logger
// cloudflared's plumbing requires.
func zerologger(log *slog.Logger) *zerolog.Logger {
	l := zerolog.New(slogWriter{log: log}).With().Str("component", "tunnel").Logger()
	return &l
}
