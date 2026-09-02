package cloudflare

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

// slogWriter adapts zerolog's io.Writer sink onto slog so cloudflared tunnel
// logs surface through the tunnel's configured logger instead of being
// discarded. zerolog accepts any io.Writer; slog has no matching ingress
// writer, so each emitted line is forwarded as a record at the level the line
// itself carries.
type slogWriter struct {
	log    *slog.Logger
	reject *edgeReject
}

var _ io.Writer = slogWriter{}

func (w slogWriter) Write(p []byte) (int, error) {
	lvl := recordLevel(p)
	if lvl >= slog.LevelError && w.reject != nil {
		if msg, ok := edgeRefusal(p); ok {
			w.reject.fire(msg)
		}
	}
	w.log.Log(context.Background(), lvl, strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// edgeReject records the first registration refusal the edge reports, so
// connect can fail on it rather than waiting out the edge budget for a
// credential no retry will fix. cloudflared retries an Unauthorized forever by
// design — it hopes the condition is edge propagation lag on a new tunnel —
// which is right for a fresh mint and never terminates for a reaped one.
//
// msg is written inside once.Do before ch closes, and every reader reaches it
// through a receive on ch, so the channel supplies the happens-before.
type edgeReject struct {
	once sync.Once
	ch   chan struct{}
	msg  string
}

func newEdgeReject() *edgeReject { return &edgeReject{ch: make(chan struct{})} }

func (r *edgeReject) fire(msg string) {
	r.once.Do(func() {
		r.msg = msg
		close(r.ch)
	})
}

// wait closes when the edge has refused the tunnel's credentials.
func (r *edgeReject) wait() <-chan struct{} { return r.ch }

// message is the edge's own words, valid once wait has closed.
func (r *edgeReject) message() string { return r.msg }

// edgeRefusal reports whether an error-level record carries the edge refusing
// the tunnel's credentials, and the message it gave.
//
// Matching a string is not a choice so much as the only option: cloudflared
// exposes no typed error for this at any layer — connection.Event carries no
// error, Supervisor.Run returns nil on every path, and upstream itself tests
// strings.Contains(err.Error(), "Unauthorized") on the value it holds
// directly. The scope is what keeps it honest: the sink is only read before
// the first connection succeeds, so a later 401 proxied from an origin has
// nothing listening.
func edgeRefusal(p []byte) (string, bool) {
	const key = `"error":"`
	i := bytes.Index(p, []byte(key))
	if i < 0 {
		return "", false
	}
	rest := p[i+len(key):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return "", false
	}
	msg := string(rest[:end])
	if !strings.Contains(msg, "Unauthorized") {
		return "", false
	}
	return msg, true
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
func zerologger(log *slog.Logger, reject *edgeReject) *zerolog.Logger {
	lvl := zerolog.WarnLevel
	if log.Enabled(context.Background(), slog.LevelDebug) {
		lvl = zerolog.DebugLevel
	}
	l := zerolog.New(slogWriter{log: log, reject: reject}).Level(lvl).With().Str("component", "tunnel").Logger()
	return &l
}
