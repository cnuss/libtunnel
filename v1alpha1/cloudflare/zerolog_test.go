package cloudflare

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// capture is a slog handler that records the level and message of every record
// it accepts, at every level, so a test can assert what the bridge forwarded
// rather than what it was handed.
type capture struct {
	levels []slog.Level
	msgs   []string
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	c.levels = append(c.levels, r.Level)
	c.msgs = append(c.msgs, r.Message)
	return nil
}
func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

// TestRecordLevelReadsZerologLevel pins the parse. zerolog writes level as the
// first field, so the bridge reads it off the prefix instead of decoding the
// record — this sits on the proxy hot path.
func TestRecordLevelReadsZerologLevel(t *testing.T) {
	for _, tc := range []struct {
		line string
		want slog.Level
	}{
		{`{"level":"error","component":"tunnel","message":"boom"}`, slog.LevelError},
		{`{"level":"fatal","message":"boom"}`, slog.LevelError},
		{`{"level":"panic","message":"boom"}`, slog.LevelError},
		{`{"level":"warn","message":"careful"}`, slog.LevelWarn},
		{`{"level":"info","message":"hello"}`, slog.LevelInfo},
		{`{"level":"debug","message":"detail"}`, slog.LevelDebug},
		{`{"level":"trace","message":"detail"}`, slog.LevelDebug},
		{`not json at all`, slog.LevelDebug},
		{`{"message":"no level field"}`, slog.LevelDebug},
		{`{"level":"unterminated`, slog.LevelDebug},
	} {
		if got := recordLevel([]byte(tc.line)); got != tc.want {
			t.Errorf("recordLevel(%s) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// TestSlogWriterForwardsAtRecordLevel pins the fix for the collapse: an error
// cloudflared reported explicitly must reach a caller running at error level,
// which is exactly where they are asking for it.
func TestSlogWriterForwardsAtRecordLevel(t *testing.T) {
	c := &capture{}
	w := slogWriter{log: slog.New(c)}

	line := `{"level":"error","component":"tunnel","error":"Unauthorized: Tunnel not found","message":"failed to serve incoming request"}`
	if _, err := w.Write([]byte(line + "\n")); err != nil {
		t.Fatal(err)
	}
	if len(c.levels) != 1 {
		t.Fatalf("wrote %d records, want 1", len(c.levels))
	}
	if c.levels[0] != slog.LevelError {
		t.Errorf("forwarded at %v, want %v", c.levels[0], slog.LevelError)
	}
	if !strings.Contains(c.msgs[0], "Unauthorized: Tunnel not found") {
		t.Errorf("message = %q, want the record verbatim", c.msgs[0])
	}
	if strings.HasSuffix(c.msgs[0], "\n") {
		t.Error("trailing newline was not trimmed")
	}
}

// TestZerologgerThreshold pins the hot-path skip. zerolog drops a sub-threshold
// event before serializing it, so a silent tunnel must still get a logger that
// refuses debug and info — otherwise every proxied request pays for JSON nobody
// reads.
func TestZerologgerThreshold(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if got := zerologger(quiet).GetLevel(); got != zerolog.WarnLevel {
		t.Errorf("info-level handler yields zerolog %v, want %v", got, zerolog.WarnLevel)
	}
	loud := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if got := zerologger(loud).GetLevel(); got != zerolog.DebugLevel {
		t.Errorf("debug-level handler yields zerolog %v, want %v", got, zerolog.DebugLevel)
	}
}
