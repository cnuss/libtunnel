package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
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
	w.log.Log(context.Background(), recordLevel(p), strings.TrimRight(string(redact(p)), "\n"))
	return len(p), nil
}

// credentials are the request headers whose values never reach a log.
var credentials = []string{"Authorization", "Cookie", "Proxy-Authorization", "Set-Cookie"}

// redact replaces the values of credentials in a record's headers, the field
// cloudflared logs each request's headers under at debug. A quote inside a
// JSON string is escaped, so a bare "headers": is only ever the field. The
// headers are re-encoded with encoding/json as zerolog encoded them, so
// everything but the redacted values comes out as it went in; a record
// without the field, or one that does not decode, is passed on as it is.
func redact(p []byte) []byte {
	field := []byte(`"headers":`)
	i := bytes.Index(p, field)
	if i < 0 {
		return p
	}
	start := i + len(field)
	dec := json.NewDecoder(bytes.NewReader(p[start:]))
	var headers map[string][]string
	if dec.Decode(&headers) != nil {
		return p
	}
	redacted := false
	for name := range headers {
		if slices.Contains(credentials, http.CanonicalHeaderKey(name)) {
			headers[name] = []string{"[redacted]"}
			redacted = true
		}
	}
	if !redacted {
		return p
	}
	b, err := json.Marshal(headers)
	if err != nil {
		return p
	}
	return slices.Concat(p[:start], b, p[start+int(dec.InputOffset()):])
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
