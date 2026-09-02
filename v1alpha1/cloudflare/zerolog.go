package cloudflare

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"

	"github.com/rs/zerolog"
)

// slogWriter adapts zerolog's io.Writer sink onto slog so cloudflared tunnel
// logs surface through the tunnel's configured logger instead of being
// discarded. zerolog accepts any io.Writer; slog has no matching ingress
// writer, so each emitted line is forwarded as a record at the level the line
// itself carries.
type slogWriter struct {
	log *slog.Logger
}

var _ io.Writer = slogWriter{}

func (w slogWriter) Write(p []byte) (int, error) {
	w.log.Log(context.Background(), recordLevel(p), strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// recordLevel reads the level off a zerolog record. zerolog writes level as the
// record's first field, so this is a prefix scan rather than a decode — the
// bridge sits on the proxy hot path and every line goes through it. Anything
// that does not match that shape reads as debug, which is how every line was
// treated before.
func recordLevel(p []byte) slog.Level {
	const prefix = `{"level":"`
	if !bytes.HasPrefix(p, []byte(prefix)) {
		return slog.LevelDebug
	}
	rest := p[len(prefix):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return slog.LevelDebug
	}
	switch string(rest[:end]) {
	case "error", "fatal", "panic":
		return slog.LevelError
	case "warn":
		return slog.LevelWarn
	case "info":
		return slog.LevelInfo
	default:
		return slog.LevelDebug
	}
}

// zerologger bridges the tunnel's slog.Logger into the *zerolog.Logger
// cloudflared's plumbing requires, with zerolog's own level set from the
// handler. zerolog drops a sub-threshold event before serializing it, so a
// silent tunnel still skips the per-event JSON encoding that sits on the proxy
// hot path — while warnings and errors, which a caller at any level wants,
// still get through.
func zerologger(log *slog.Logger) *zerolog.Logger {
	lvl := zerolog.WarnLevel
	if log.Enabled(context.Background(), slog.LevelDebug) {
		lvl = zerolog.DebugLevel
	}
	l := zerolog.New(slogWriter{log: log}).Level(lvl).With().Str("component", "tunnel").Logger()
	return &l
}
