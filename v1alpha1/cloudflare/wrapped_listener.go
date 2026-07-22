package cloudflare

// wrappedListener is the disconnect/reconnect shim between cloudflared and the
// origin for the quick-tunnel streaming-buffer problem. A trycloudflare quick
// tunnel buffers a chunked 200 response at the edge and flushes on a CLEAN
// response end (terminal chunk). Headers, content-type, transport, and idle
// are all ignored; an abort discards the buffer. The shim exploits that
// trigger behind a public backend knob:
//
//	cloudflared --dials--> wrappedListener ==session==> origin (one conn)
//
//	session: origin response head + de-chunked payload frames -> frameBuffer
//	         downstream conns come and go; each gets a replayed head and
//	         re-chunked frames.
//
//	chop: every chop interval the current downstream response is ended CLEANLY
//	         (terminal chunk) and closed — the edge flushes — and the next
//	         reconnect resumes from the buffer.
//
// The origin never sees the churn: its single connection streams into the
// buffer for the session's whole life. Sessions are keyed by the request
// line, so a client re-issuing the identical request (kubectl re-watching)
// reattaches; a different request starts its own session.
//
// Only STREAMING origin responses (Transfer-Encoding: chunked with no
// Content-Length) take the de-chunk/chop path above. A FIXED response
// (Content-Length, or a close-delimited body — e.g. apiserver /healthz) is
// relayed VERBATIM to one downstream conn — exact head bytes, body copied
// through untouched — then the session finishes; there is nothing to chop.
//
// cloudflared reaches the shim over plaintext (the shim listens on a plain TCP
// socket); the shim re-dials the origin itself, adding TLS on that hop when the
// origin scheme is https (InsecureSkipVerify, matching the engine's always-off
// origin verification).

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// wrappedListener implements net.Listener; cloudflared dials Addr(). It owns
// the accept loop and the session table. chop is fixed at construction and
// never mutated after the serve loop starts.
type wrappedListener struct {
	net.Listener // cf-facing TCP listener

	target    string // origin host:port
	originTLS bool   // dial the origin over TLS (InsecureSkipVerify) when set
	log       *slog.Logger
	ctx       context.Context
	chop      time.Duration // downstream clean-close cadence; 0 = never chop

	mu       sync.Mutex
	sessions map[string]*session
}

// newWrappedListener binds the cf-facing listener and starts the accept loop.
// target is the origin's host:port; originTLS dials that origin over TLS
// (InsecureSkipVerify, matching the backend's always-off origin verification).
// chop is the clean-close cadence (0 = never chop).
func newWrappedListener(ctx context.Context, log *slog.Logger, target string, originTLS bool, chop time.Duration) (*wrappedListener, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	w := &wrappedListener{
		Listener:  l,
		target:    target,
		originTLS: originTLS,
		log:       log,
		ctx:       ctx,
		chop:      chop,
		sessions:  map[string]*session{},
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	go w.serve()
	log.Info("wrapped listener interposed", "listen", l.Addr().String(), "target", target, "originTLS", originTLS, "chop", chop)
	return w, nil
}

// Accept implements net.Listener verbatim; session dispatch happens in the
// serve loop so Accept keeps net.Listener semantics.
func (w *wrappedListener) Accept() (net.Conn, error) {
	return w.Listener.Accept()
}

// serve accepts downstream connections and dispatches each to its session by
// request line.
func (w *wrappedListener) serve() {
	for {
		conn, err := w.Accept()
		if err != nil {
			return
		}
		go w.dispatch(conn)
	}
}

// dispatch reads the downstream request head and hands the connection to the
// matching live session, or starts a new session for it.
func (w *wrappedListener) dispatch(conn net.Conn) {
	reqLine, reqHead, err := readHead(conn)
	if err != nil {
		w.log.Debug("wrapped listener: bad downstream request head", "error", err)
		conn.Close()
		return
	}

	w.mu.Lock()
	s := w.sessions[reqLine]
	if s == nil || s.closed() {
		s = newSession(w, reqLine, reqHead)
		w.sessions[reqLine] = s
	}
	w.mu.Unlock()

	s.attach(conn)
}

// drop removes a finished session from the table.
func (w *wrappedListener) drop(s *session) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sessions[s.reqLine] == s {
		delete(w.sessions, s.reqLine)
	}
}

// session is one logical origin stream served across many short downstream
// responses. The origin connection lives for the whole session.
type session struct {
	w       *wrappedListener
	reqLine string

	head   []byte       // origin response head (status line + headers + CRLF)
	frames *frameBuffer // de-chunked payload frames from the origin

	// Fixed-response passthrough (non-streaming origin). Set by upstream before
	// headReady closes, so headReady's close synchronizes them for downstream.
	// When fixed, upstream hands the live origin conn/reader to downstream for a
	// verbatim relay instead of de-chunking into frames.
	fixed      bool
	originConn net.Conn      // live origin conn, owned by downstream on the fixed path
	originBR   *bufio.Reader // buffered origin reader positioned at the body start
	originStop func() bool   // cancels the ctx-cancel AfterFunc on originConn
	bodyLen    int64         // Content-Length, or -1 for a close-delimited body

	headReady chan struct{} // closed once head is parsed
	doneCh    chan struct{} // closed when the origin stream has fully ended
	doneOnce  sync.Once     // guards the single close of doneCh
	closedCh  chan struct{} // closed when the session is finished and unroutable

	mu       sync.Mutex
	upErr    error
	attached chan net.Conn // reconnecting downstream conns queue here
}

// closeDone marks the origin stream ended, exactly once. Both upstream (on the
// streaming path / failures) and downstream (on the fixed relay) reach it.
func (s *session) closeDone() {
	s.doneOnce.Do(func() { close(s.doneCh) })
}

func newSession(w *wrappedListener, reqLine string, reqHead []byte) *session {
	s := &session{
		w:         w,
		reqLine:   reqLine,
		frames:    newFrameBuffer(),
		headReady: make(chan struct{}),
		doneCh:    make(chan struct{}),
		closedCh:  make(chan struct{}),
		attached:  make(chan net.Conn, 4),
	}
	go s.upstream(reqHead)
	go s.downstream()
	return s
}

// done reports that the origin stream has fully ended. Buffered frames may
// still be pending — done is not the same as finished (see closed).
func (s *session) done() bool {
	select {
	case <-s.doneCh:
		return true
	default:
		return false
	}
}

// closed reports that the session is finished: the stream ended AND every
// buffered frame has been served (or it timed out / failed). Once closed a
// session is dropped from the table, so dispatch must start a fresh one.
// dispatch keys reuse on closed, not done, so reconnects arriving while the
// buffer still drains reattach to the live session instead of re-dialing the
// origin.
func (s *session) closed() bool {
	select {
	case <-s.closedCh:
		return true
	default:
		return false
	}
}

// attach queues a downstream connection for the serving loop. A conn arriving
// after the session has closed is refused (closed), not queued — attach keys on
// closed, not done, so a reconnect during frame drain still reattaches.
func (s *session) attach(conn net.Conn) {
	select {
	case <-s.closedCh:
		conn.Close()
		return
	default:
	}
	select {
	case s.attached <- conn:
	case <-s.closedCh:
		conn.Close()
	}
}

// upstream owns the session's single origin connection: it forwards the
// original request head and parses the response head, then branches on framing.
// A STREAMING response (chunked, no Content-Length — the watch shape) is
// de-chunked into the buffer here until the origin finishes. A FIXED response
// (Content-Length, or otherwise not chunked) is handed to downstream for a
// verbatim relay: upstream stashes the live conn/reader and returns, leaving
// origin teardown to downstream.
func (s *session) upstream(reqHead []byte) {
	up, err := s.dialOrigin()
	if err != nil {
		s.fail(fmt.Errorf("origin dial: %w", err))
		s.closeDone()
		return
	}
	stop := context.AfterFunc(s.w.ctx, func() { up.Close() })

	if _, err := up.Write(reqHead); err != nil {
		stop()
		up.Close()
		s.fail(fmt.Errorf("origin request: %w", err))
		s.closeDone()
		return
	}

	br := bufio.NewReader(up)
	_, head, err := readHeadFrom(br)
	if err != nil {
		stop()
		up.Close()
		s.fail(fmt.Errorf("origin response head: %w", err))
		s.closeDone()
		return
	}
	s.head = head

	if !streamingHead(head) {
		// Fixed-length or close-delimited: relay verbatim. Hand the live origin
		// conn/reader to downstream (which serves exactly one response and tears
		// the origin down); upstream is done. No de-chunking, no frameBuffer.
		s.fixed = true
		s.originConn = up
		s.originBR = br
		s.originStop = stop
		s.bodyLen = contentLength(head)
		close(s.headReady)
		return
	}

	// Streaming path. Only the origin stream ends here; the session stays
	// routable (in the table) until downstream has served every buffered frame.
	// downstream owns closedCh and the table drop, so a reconnect during drain
	// reattaches instead of re-dialing the origin.
	defer stop()
	defer up.Close()
	defer s.closeDone()
	close(s.headReady)

	// De-chunk the body into whole frames. The origin flushes complete
	// events per chunk, so frame boundaries are safe places to chop a
	// downstream response without tearing a JSON line.
	for {
		frame, err := readChunk(br)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.w.log.Debug("wrapped listener: origin stream error", "session", s.reqLine, "error", err)
			}
			s.frames.CloseWriter()
			return
		}
		if frame == nil { // terminal chunk: origin response complete
			s.frames.CloseWriter()
			return
		}
		s.frames.Write(frame)
	}
}

// dialOrigin opens the session's origin connection, adding TLS on the origin
// hop when the ingress scheme was https. Verification is off (InsecureSkipVerify)
// to match the rest of the engine, which sets NoTLSVerify for the origin — a
// local origin may carry a self-signed cert.
func (s *session) dialOrigin() (net.Conn, error) {
	if s.w.originTLS {
		return tls.Dial("tcp", s.w.target, &tls.Config{InsecureSkipVerify: true})
	}
	return net.Dial("tcp", s.w.target)
}

func (s *session) fail(err error) {
	s.mu.Lock()
	s.upErr = err
	s.mu.Unlock()
	s.frames.CloseWriter()
	s.w.log.Warn("wrapped listener: session failed", "session", s.reqLine, "error", err)
}

// downstream serves the session's frames across successive downstream
// connections: replayed head, re-chunked frames, and a clean terminal chunk
// at every chop (edge flush) or at the stream's true end.
func (s *session) downstream() {
	// downstream is the session's lifecycle owner: when it returns the session
	// is finished, so it closes closedCh (routing sees it as gone), drops it
	// from the table, and closes any conns that raced in after the close.
	defer func() {
		close(s.closedCh)
		s.w.drop(s)
		for {
			select {
			case conn := <-s.attached:
				conn.Close()
			default:
				return
			}
		}
	}()

	first := true
	for {
		var conn net.Conn
		select {
		case conn = <-s.attached:
		case <-s.doneCh:
			if s.frames.Drained() {
				return
			}
			// Origin finished but frames remain: keep serving reconnects
			// until drained or nobody comes back.
			select {
			case conn = <-s.attached:
			case <-time.After(15 * time.Second):
				return
			}
		}

		// Reconnects re-send a request head; it was consumed in dispatch.
		// The first conn's head was forwarded upstream by the session.
		if !first {
			s.w.log.Debug("wrapped listener: downstream reattached", "session", s.reqLine)
		}
		first = false
		s.serveOne(conn)

		if s.done() && s.frames.Drained() {
			return
		}
	}
}

// serveOne writes one downstream response on conn. For a STREAMING session:
// head, frames until the chop interval elapses or the stream ends, then a clean
// terminal chunk. For a FIXED session: the exact origin head, then the body
// copied through verbatim, then the origin is torn down and the session
// finished — it serves this one response only.
func (s *session) serveOne(conn net.Conn) {
	defer conn.Close()

	select {
	case <-s.headReady:
	case <-s.doneCh:
		return // upstream failed before a head existed; nothing to replay
	}

	if s.fixed {
		// Verbatim relay of a non-streaming response. Teardown runs regardless
		// of write outcome, so the session finishes as soon as this one response
		// is served (or the client vanishes): origin conn closed, doneCh closed,
		// frames closed so downstream sees Drained and returns.
		defer func() {
			s.originStop()
			s.originConn.Close()
			s.frames.CloseWriter()
			s.closeDone()
		}()
		if _, err := conn.Write(s.head); err != nil {
			return
		}
		if s.bodyLen >= 0 {
			_, _ = io.CopyN(conn, s.originBR, s.bodyLen)
		} else {
			_, _ = io.Copy(conn, s.originBR) // close-delimited: to EOF
		}
		return
	}

	if _, err := conn.Write(s.head); err != nil {
		return
	}

	var deadline <-chan time.Time
	if s.w.chop > 0 {
		deadline = time.After(s.w.chop)
	}

	for {
		frame, ok := s.frames.Read(deadline)
		if frame != nil {
			if err := writeChunk(conn, frame); err != nil {
				return // downstream died mid-write; frame is lost (kube
				// resourceVersion re-request would recover it in real use)
			}
		}
		if !ok { // chop deadline or stream end: finish this response cleanly
			_, _ = conn.Write([]byte("0\r\n\r\n"))
			return
		}
	}
}

// frameBuffer is the session's payload queue: whole de-chunked frames in,
// frames out in order, single consumer. Read returns (frame, true) for a
// frame, (nil-or-frame, false) when the deadline fires or the writer closed
// — false always means "end the current downstream response now".
type frameBuffer struct {
	mu     sync.Mutex
	cond   *sync.Cond
	frames [][]byte
	closed bool
}

func newFrameBuffer() *frameBuffer {
	fb := &frameBuffer{}
	fb.cond = sync.NewCond(&fb.mu)
	return fb
}

func (fb *frameBuffer) Write(frame []byte) {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.frames = append(fb.frames, frame)
	fb.cond.Broadcast()
}

// Read pops the next frame, waiting until one arrives, the writer closes, or
// deadline fires. The deadline is checked via a waker goroutine because
// sync.Cond has no timed wait.
func (fb *frameBuffer) Read(deadline <-chan time.Time) ([]byte, bool) {
	expired := make(chan struct{})
	if deadline != nil {
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			select {
			case <-deadline:
				close(expired)
				fb.cond.Broadcast()
			case <-stop:
			}
		}()
	}
	fb.mu.Lock()
	defer fb.mu.Unlock()
	for {
		select {
		case <-expired:
			if len(fb.frames) > 0 {
				return fb.pop(), false // deliver, then end the response
			}
			return nil, false
		default:
		}
		if len(fb.frames) > 0 {
			return fb.pop(), true
		}
		if fb.closed {
			return nil, false
		}
		fb.cond.Wait()
	}
}

// pop removes and returns the head frame; callers hold fb.mu.
func (fb *frameBuffer) pop() []byte {
	f := fb.frames[0]
	fb.frames = fb.frames[1:]
	return f
}

func (fb *frameBuffer) CloseWriter() {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	fb.closed = true
	fb.cond.Broadcast()
}

// Drained reports writer-closed with no frames pending.
func (fb *frameBuffer) Drained() bool {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return fb.closed && len(fb.frames) == 0
}

// readHead consumes an HTTP head (request or response) from c: everything
// through the blank line. Returns the first line and the raw head bytes.
func readHead(c net.Conn) (string, []byte, error) {
	return readHeadFrom(bufio.NewReader(c))
}

func readHeadFrom(br *bufio.Reader) (string, []byte, error) {
	var head []byte
	var first string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", nil, err
		}
		head = append(head, line...)
		trimmed := trimCRLF(line)
		if first == "" {
			first = trimmed
		}
		if trimmed == "" {
			return first, head, nil
		}
		if len(head) > 64<<10 {
			return "", nil, errors.New("head too large")
		}
	}
}

// streamingHead reports whether an origin response head describes a streaming
// body the shim should de-chunk and chop: Transfer-Encoding: chunked (case
// -insensitive) AND no Content-Length. Everything else — fixed Content-Length,
// or an HTTP/1.0-style close-delimited body — is a non-streaming response the
// shim relays verbatim. The watch path (chunked, no length) is streaming;
// /healthz (Content-Length: 2) is not.
func streamingHead(head []byte) bool {
	te := strings.ToLower(headerValue(head, "Transfer-Encoding"))
	return strings.Contains(te, "chunked") && headerValue(head, "Content-Length") == ""
}

// contentLength returns the response's Content-Length, or -1 when absent or
// unparsable (relay to EOF).
func contentLength(head []byte) int64 {
	v := headerValue(head, "Content-Length")
	if v == "" {
		return -1
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// headerValue returns the first value of header name (case-insensitive) from a
// raw HTTP head (status line + header lines + blank line), or "" if absent.
func headerValue(head []byte, name string) string {
	want := strings.ToLower(name)
	for _, line := range strings.Split(string(head), "\n") {
		line = trimCRLF(line)
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:i])) == want {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

// readChunk reads one chunk of a chunked body: (payload, nil) for a data
// chunk, (nil, nil) for the terminal chunk (trailers consumed), or an error.
func readChunk(br *bufio.Reader) ([]byte, error) {
	sizeLine, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	sizeStr := trimCRLF(sizeLine)
	if i := strings.IndexByte(sizeStr, ';'); i >= 0 {
		sizeStr = sizeStr[:i] // drop chunk extensions
	}
	size, err := strconv.ParseInt(sizeStr, 16, 64)
	if err != nil {
		return nil, fmt.Errorf("bad chunk size %q: %w", sizeStr, err)
	}
	if size == 0 {
		// Terminal chunk: consume (empty) trailer section through its CRLF.
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return nil, err
			}
			if trimCRLF(line) == "" {
				return nil, nil
			}
		}
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, err
	}
	// Trailing CRLF after the chunk data.
	if _, err := br.Discard(2); err != nil {
		return nil, err
	}
	return payload, nil
}

// writeChunk writes one chunked-encoding data chunk.
func writeChunk(w io.Writer, payload []byte) error {
	if _, err := fmt.Fprintf(w, "%x\r\n", len(payload)); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func trimCRLF(s string) string {
	return strings.TrimRight(s, "\r\n")
}
