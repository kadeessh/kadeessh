package actors

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/kadeessh/kadeessh/internal/session"
	"github.com/kadeessh/kadeessh/internal/ssh"
)

// mockSession implements session.Session for testing.
type mockSession struct {
	user       string
	remoteAddr net.Addr
	localAddr  net.Addr
	ctx        context.Context
	stderr     *mockReadWriter
	written    []byte

	pty      ssh.Pty
	winCh    <-chan ssh.Window
	hasPty   bool
	ptyCalls int32
}

func (m *mockSession) User() string             { return m.user }
func (m *mockSession) RemoteAddr() net.Addr     { return m.remoteAddr }
func (m *mockSession) LocalAddr() net.Addr      { return m.localAddr }
func (m *mockSession) Context() context.Context { return m.ctx }
func (m *mockSession) Read(data []byte) (int, error) {
	return 0, io.EOF
}

func (m *mockSession) Write(data []byte) (int, error) {
	m.written = append(m.written, data...)
	return len(data), nil
}
func (m *mockSession) Close() error      { return nil }
func (m *mockSession) CloseWrite() error { return nil }
func (m *mockSession) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}

func (m *mockSession) Stderr() io.ReadWriter {
	if m.stderr == nil {
		m.stderr = &mockReadWriter{}
	}
	return m.stderr
}
func (m *mockSession) Signals(c chan<- ssh.Signal) {}
func (m *mockSession) Break(c chan<- bool)         {}
func (m *mockSession) Environ() []string           { return nil }
func (m *mockSession) Command() []string           { return nil }
func (m *mockSession) RawCommand() string          { return "" }
func (m *mockSession) Subsystem() string           { return "" }
func (m *mockSession) PublicKey() ssh.PublicKey    { return nil }
func (m *mockSession) Permissions() ssh.Permissions {
	return ssh.Permissions{}
}

func (m *mockSession) Pty() (ssh.Pty, <-chan ssh.Window, bool) {
	atomic.AddInt32(&m.ptyCalls, 1)
	return m.pty, m.winCh, m.hasPty
}

type mockAddr struct{ addr string }

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string  { return m.addr }

type mockReadWriter struct {
	written []byte
}

func (m *mockReadWriter) Read(p []byte) (int, error) { return 0, io.EOF }
func (m *mockReadWriter) Write(p []byte) (int, error) {
	m.written = append(m.written, p...)
	return len(p), nil
}

// mockHandler is a configurable session.Handler used by tests.
type mockHandler struct {
	handled bool
	fn      func(sess session.Session) error
}

func (m *mockHandler) Handle(sess session.Session) error {
	m.handled = true
	if m.fn != nil {
		return m.fn(sess)
	}
	_, _ = sess.Write([]byte("Hello from mock handler\n"))
	return nil
}

// mockStorage implements certmagic.Storage for testing.
type mockStorage struct {
	data      map[string][]byte
	storeErr  error
	storeHook func(key string, value []byte)
}

func newMockStorage() *mockStorage { return &mockStorage{data: map[string][]byte{}} }

func (m *mockStorage) Store(ctx context.Context, key string, value []byte) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	if m.storeHook != nil {
		m.storeHook(key, value)
	}
	buf := make([]byte, len(value))
	copy(buf, value)
	m.data[key] = buf
	return nil
}

func (m *mockStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if v, ok := m.data[key]; ok {
		return v, nil
	}
	return nil, errors.New("not found")
}

func (m *mockStorage) Delete(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockStorage) Exists(ctx context.Context, key string) bool {
	_, ok := m.data[key]
	return ok
}

func (m *mockStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	return nil, nil
}

func (m *mockStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	return certmagic.KeyInfo{}, nil
}
func (m *mockStorage) Lock(ctx context.Context, key string) error   { return nil }
func (m *mockStorage) Unlock(ctx context.Context, key string) error { return nil }

// splitCastLines returns the header and event lines of a cast file.
func splitCastLines(t *testing.T, b []byte) (asciinemaHeader, [][]interface{}) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) == 0 {
		t.Fatalf("empty recording")
	}
	var h asciinemaHeader
	if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
		t.Fatalf("bad header: %v — line: %q", err, lines[0])
	}
	events := make([][]interface{}, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		var ev []interface{}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad event %q: %v", line, err)
		}
		events = append(events, ev)
	}
	return h, events
}

func newTestSession(user, sessionID string) *mockSession {
	ctx := context.WithValue(context.Background(), ssh.ContextKeySessionID, sessionID)
	ctx = context.WithValue(ctx, ssh.ContextKeyClientVersion, "SSH-2.0-testclient")
	return &mockSession{
		user:       user,
		remoteAddr: &mockAddr{"192.168.1.100:54321"},
		localAddr:  &mockAddr{"10.0.0.1:22"},
		ctx:        ctx,
	}
}

func newTestRecorderActor(t *testing.T, handler session.Handler, storage certmagic.Storage) *AsciinemaRecorder {
	t.Helper()
	trueVal := true
	return &AsciinemaRecorder{
		handler:          handler,
		storage:          storage,
		logger:           caddy.Log(),
		OnRecordingError: "continue",
		IncludeMetadata:  &trueVal,
		TempDir:          t.TempDir(),
	}
}

// newTestRecorder builds an asciinemaRecorder with sensible defaults and an
// open temp file in a per-test directory. Fields set on the input struct
// override the defaults; unset ones are filled in.
func newTestRecorder(t *testing.T, r *asciinemaRecorder) *asciinemaRecorder {
	t.Helper()
	if r.storage == nil {
		r.storage = newMockStorage()
	}
	if r.storagePath == "" {
		r.storagePath = "test.cast"
	}
	if r.header.Version == 0 {
		r.header = asciinemaHeader{Version: 2, Width: 80, Height: 24}
	}
	if r.startTime.IsZero() {
		r.startTime = time.Now()
	}
	if r.logger == nil {
		r.logger = caddy.Log()
	}
	if err := r.openTempFile(t.TempDir()); err != nil {
		t.Fatalf("openTempFile: %v", err)
	}
	return r
}

func TestSanitizeFilenamePart(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"alice", "alice"},
		{"", "unknown"},
		{"../../etc/passwd", "etc_passwd"},
		{"user with spaces", "user_with_spaces"},
		{"..", "unknown"},
		{".hidden", "hidden"},
		{"a/b\\c", "a_b_c"},
		{"user:name", "user_name"},
		{"user.name", "user_name"},
		{strings.Repeat("x", 200), strings.Repeat("x", maxFilenamePartLen)},
	}
	for _, tc := range tests {
		got := sanitizeFilenamePart(tc.in)
		if got != tc.want {
			t.Errorf("sanitizeFilenamePart(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.ContainsAny(got, "/\\.") {
			t.Errorf("sanitizeFilenamePart(%q) still contains unsafe chars: %q", tc.in, got)
		}
	}
}

func TestAsciinemaRecorder_Handle_BasicRecording(t *testing.T) {
	storage := newMockStorage()
	handler := &mockHandler{}
	rec := newTestRecorderActor(t, handler, storage)
	sess := newTestSession("testuser", "test-session-123")

	if err := rec.Handle(sess); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !handler.handled {
		t.Fatal("inner handler not invoked")
	}
	if len(storage.data) != 1 {
		t.Fatalf("expected 1 recording stored, got %d", len(storage.data))
	}

	var key string
	for k := range storage.data {
		key = k
	}
	if !strings.HasPrefix(key, "ssh/recordings/") {
		t.Errorf("unexpected storage key: %s", key)
	}
	if !strings.Contains(key, "testuser-test-session-123") {
		t.Errorf("storage key missing user/session: %s", key)
	}

	header, events := splitCastLines(t, storage.data[key])
	if header.Version != 2 {
		t.Errorf("version = %d, want 2", header.Version)
	}
	// SSH metadata must live under the tool-scoped "kadeessh" field, not in env.
	if header.Kadeessh == nil {
		t.Fatal("header.Kadeessh missing; SSH metadata should be under the kadeessh field")
	}
	if header.Kadeessh.User != "testuser" {
		t.Errorf("kadeessh.user = %q, want testuser", header.Kadeessh.User)
	}
	if header.Kadeessh.SessionID != "test-session-123" {
		t.Errorf("kadeessh.session_id = %q", header.Kadeessh.SessionID)
	}
	if header.Kadeessh.ClientVersion != "SSH-2.0-testclient" {
		t.Errorf("kadeessh.client_version = %q", header.Kadeessh.ClientVersion)
	}
	if header.Kadeessh.Client == "" {
		t.Error("kadeessh.client should be populated from RemoteAddr")
	}
	if header.Kadeessh.Server == "" {
		t.Error("kadeessh.server should be populated from LocalAddr")
	}
	// env should hold only real terminal environment variables.
	for k := range header.Env {
		if strings.HasPrefix(k, "SSH_") {
			t.Errorf("env should not contain SSH_* keys, got %q", k)
		}
	}
	if len(events) < 1 {
		t.Fatalf("expected at least 1 event, got 0")
	}
	// First event should be output "o" with the handler's write.
	if events[0][1] != "o" {
		t.Errorf("first event type = %v, want o", events[0][1])
	}
	if !strings.Contains(events[0][2].(string), "Hello from mock handler") {
		t.Errorf("output event content: %v", events[0][2])
	}
}

func TestAsciinemaRecorder_FilenameSanitization(t *testing.T) {
	storage := newMockStorage()
	handler := &mockHandler{}
	rec := newTestRecorderActor(t, handler, storage)
	sess := newTestSession("../../etc/passwd", "abcdef123")

	if err := rec.Handle(sess); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	for key := range storage.data {
		if strings.Contains(key, "..") {
			t.Errorf("storage key still contains dot segments: %s", key)
		}
		if !strings.HasPrefix(key, "ssh/recordings/") {
			t.Errorf("storage key escaped prefix: %s", key)
		}
		segments := strings.Split(key, "/")
		if len(segments) != 4 {
			t.Errorf("expected 4 path segments, got %d in %s", len(segments), key)
		}
		last := segments[len(segments)-1]
		if !strings.HasSuffix(last, ".cast") {
			t.Errorf("expected .cast extension: %s", last)
		}
		// Filename component (excluding .cast extension) must not contain dots.
		base := strings.TrimSuffix(last, ".cast")
		if strings.Contains(base, ".") {
			t.Errorf("filename base still contains dots: %s", base)
		}
	}
}

func TestAsciinemaRecorder_CollisionAppendsSuffix(t *testing.T) {
	storage := newMockStorage()
	handler := &mockHandler{}
	rec := newTestRecorderActor(t, handler, storage)

	// Pre-seed a file at the path the recorder will pick.
	date := time.Now().Format("2006-01-02")
	preExisting := "ssh/recordings/" + date + "/alice-sid1.cast"
	storage.data[preExisting] = []byte("pre-existing")

	sess := newTestSession("alice", "sid1")
	if err := rec.Handle(sess); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if string(storage.data[preExisting]) != "pre-existing" {
		t.Errorf("pre-existing recording was overwritten")
	}
	if len(storage.data) != 2 {
		t.Errorf("expected 2 entries (original + new), got %d", len(storage.data))
	}
}

func TestAsciinemaRecorder_MaxSizeEmitsMarker(t *testing.T) {
	r := newTestRecorder(t, &asciinemaRecorder{maxSize: 20})

	// First write should fit within the limit
	if _, err := r.Write([]byte("hi")); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	// Second write exceeds the limit
	if _, err := r.Write([]byte(strings.Repeat("X", 200))); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	// Further writes should be silently dropped
	if _, err := r.Write([]byte("dropped")); err != nil {
		t.Fatalf("write 3: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	storage := r.storage.(*mockStorage)
	_, events := splitCastLines(t, storage.data["test.cast"])
	sawMarker := false
	for _, ev := range events {
		if ev[1] == "m" {
			sawMarker = true
			data := ev[2].(string)
			if !strings.Contains(data, "max_size") {
				t.Errorf("marker missing reason: %q", data)
			}
		}
	}
	if !sawMarker {
		t.Error("expected truncation marker event, got none")
	}
	if !r.wasTruncated() {
		t.Error("wasTruncated() = false, want true")
	}
}

func TestAsciinemaRecorder_MaxDurationEmitsMarker(t *testing.T) {
	r := newTestRecorder(t, &asciinemaRecorder{
		startTime:   time.Now().Add(-time.Hour),
		maxDuration: time.Millisecond,
	})
	if _, err := r.Write([]byte("late")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	storage := r.storage.(*mockStorage)
	_, events := splitCastLines(t, storage.data["test.cast"])
	if len(events) != 1 || events[0][1] != "m" {
		t.Fatalf("expected exactly one marker event, got %v", events)
	}
	if !strings.Contains(events[0][2].(string), "max_duration") {
		t.Errorf("marker reason: %v", events[0][2])
	}
}

func TestAsciinemaRecorder_ResizeEventCaptured(t *testing.T) {
	winCh := make(chan ssh.Window, 4)
	storage := newMockStorage()
	handler := &mockHandler{
		fn: func(sess session.Session) error {
			// Actor consumes the (fan-out) PTY channel; this is what
			// Shell would do to react to window changes.
			_, fwd, ok := sess.Pty()
			if !ok {
				t.Fatalf("Pty() returned ok=false in inner handler")
			}
			winCh <- ssh.Window{Width: 100, Height: 40}
			winCh <- ssh.Window{Width: 120, Height: 50}
			close(winCh)
			// Drain forwarded channel so the fan-out goroutine can exit.
			for range fwd {
			}
			return nil
		},
	}
	rec := newTestRecorderActor(t, handler, storage)
	sess := newTestSession("alice", "sid-resize")
	sess.pty = ssh.Pty{Term: "xterm-256color", Window: ssh.Window{Width: 80, Height: 24}}
	sess.winCh = winCh
	sess.hasPty = true

	if err := rec.Handle(sess); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	var recordingKey string
	for k := range storage.data {
		recordingKey = k
	}
	header, events := splitCastLines(t, storage.data[recordingKey])
	if header.Width != 80 || header.Height != 24 {
		t.Errorf("initial dims %dx%d, want 80x24", header.Width, header.Height)
	}
	var resizes []string
	for _, ev := range events {
		if ev[1] == "r" {
			resizes = append(resizes, ev[2].(string))
		}
	}
	if len(resizes) != 2 {
		t.Fatalf("expected 2 resize events, got %d (events=%v)", len(resizes), events)
	}
	if resizes[0] != "100x40" || resizes[1] != "120x50" {
		t.Errorf("resize events = %v, want [100x40 120x50]", resizes)
	}
}

func TestAsciinemaRecorder_StderrRecorded(t *testing.T) {
	storage := newMockStorage()
	handler := &mockHandler{
		fn: func(sess session.Session) error {
			_, _ = sess.Write([]byte("out\n"))
			_, _ = sess.Stderr().Write([]byte("err\n"))
			return nil
		},
	}
	rec := newTestRecorderActor(t, handler, storage)
	sess := newTestSession("alice", "sid-stderr")

	if err := rec.Handle(sess); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	var key string
	for k := range storage.data {
		key = k
	}
	_, events := splitCastLines(t, storage.data[key])
	if len(events) != 2 {
		t.Fatalf("expected 2 events (stdout + stderr), got %d", len(events))
	}
	if events[0][2].(string) != "out\n" || events[1][2].(string) != "err\n" {
		t.Errorf("event contents = %v, %v", events[0][2], events[1][2])
	}
}

func TestAsciinemaRecorder_OnErrorReject(t *testing.T) {
	storage := &mockStorage{data: map[string][]byte{}, storeErr: errors.New("boom")}
	handler := &mockHandler{
		fn: func(sess session.Session) error {
			_, _ = sess.Write([]byte("hi"))
			return nil
		},
	}
	falseVal := false
	rec := &AsciinemaRecorder{
		handler:          handler,
		storage:          storage,
		logger:           caddy.Log(),
		OnRecordingError: "reject",
		IncludeMetadata:  &falseVal,
		TempDir:          t.TempDir(),
	}
	// newRecorder succeeds (temp file opens fine); the storage error surfaces
	// at Close. Storage failures should be logged but not fail the session
	// itself — the client already got their output. The temp file is
	// preserved for manual recovery.
	sess := newTestSession("alice", "sid-err")
	if err := rec.Handle(sess); err != nil {
		t.Fatalf("Handle should not fail on close error under reject: %v", err)
	}
	if !handler.handled {
		t.Error("handler was not invoked")
	}
}

func TestAsciinemaRecorder_PeriodicFlush(t *testing.T) {
	r := newTestRecorder(t, &asciinemaRecorder{
		storagePath:   "flushtest.cast",
		flushInterval: 10 * time.Millisecond,
	})
	r.startFlusher()
	if _, err := r.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The bufio buffer holds the write until fsync; poll the temp file on
	// disk to confirm the periodic flusher persisted it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(r.tempPath); err == nil && bytes.Contains(data, []byte("hello")) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	data, err := os.ReadFile(r.tempPath)
	if err != nil {
		t.Fatalf("read temp: %v", err)
	}
	if !bytes.Contains(data, []byte("hello")) {
		t.Fatalf("no periodic fsync observed within 2s; temp file: %q", data)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	storage := r.storage.(*mockStorage)
	if _, ok := storage.data["flushtest.cast"]; !ok {
		t.Fatal("recording missing from storage after close")
	}
	// Temp file should be removed on successful upload.
	if _, err := os.Stat(r.tempPath); !os.IsNotExist(err) {
		t.Errorf("temp file %s still exists after successful upload: err=%v", r.tempPath, err)
	}
}

func TestAsciinemaRecorder_CloseIdempotent(t *testing.T) {
	r := newTestRecorder(t, &asciinemaRecorder{storagePath: "idem.cast"})
	if err := r.Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close 2: %v", err)
	}
}

func TestAsciinemaRecorder_UploadFailurePreservesTempFile(t *testing.T) {
	storage := &mockStorage{data: map[string][]byte{}, storeErr: errors.New("upload denied")}
	r := newTestRecorder(t, &asciinemaRecorder{
		storage:     storage,
		storagePath: "preserve.cast",
	})
	if _, err := r.Write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	tempPath := r.tempPath
	err := r.Close()
	if err == nil {
		t.Fatal("expected Close to return storage error, got nil")
	}
	if !strings.Contains(err.Error(), tempPath) {
		t.Errorf("error should reference preserved temp path %q, got %q", tempPath, err)
	}
	if _, statErr := os.Stat(tempPath); statErr != nil {
		t.Fatalf("temp file %s should have been preserved on upload failure: %v", tempPath, statErr)
	}
	// The preserved temp file must itself be a valid cast (header + events).
	data, err := os.ReadFile(tempPath)
	if err != nil {
		t.Fatalf("read temp: %v", err)
	}
	header, events := splitCastLines(t, data)
	if header.Version != 2 {
		t.Errorf("preserved cast header version = %d, want 2", header.Version)
	}
	if len(events) == 0 || events[0][2].(string) != "payload" {
		t.Errorf("preserved cast missing payload event: %v", events)
	}
}

func TestAsciinemaRecorder_NoPtyDefaultDims(t *testing.T) {
	storage := newMockStorage()
	handler := &mockHandler{}
	rec := newTestRecorderActor(t, handler, storage)
	sess := newTestSession("alice", "sid-nopty")
	// hasPty defaults to false

	if err := rec.Handle(sess); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	var key string
	for k := range storage.data {
		key = k
	}
	header, _ := splitCastLines(t, storage.data[key])
	if header.Width != 80 || header.Height != 24 {
		t.Errorf("dims = %dx%d, want 80x24", header.Width, header.Height)
	}
	if header.Env["TERM"] == "" {
		t.Error("TERM env missing in no-PTY session")
	}
}

// writeOrphanTempFile drops a synthetic crashed-session temp file into dir,
// tagged with the given PID segment, and returns its path. If body is nil a
// minimally valid cast (header + one event) is generated with the given
// user/sessionID so path derivation can be exercised.
func writeOrphanTempFile(t *testing.T, dir, pidSegment, user, sessionID string, body []byte) string {
	t.Helper()
	name := fmt.Sprintf("%s%s-orphan%d.cast", tempFilePrefix, pidSegment, time.Now().UnixNano())
	p := filepath.Join(dir, name)
	if body == nil {
		h := asciinemaHeader{
			Version:   2,
			Width:     80,
			Height:    24,
			Timestamp: time.Now().Unix(),
			Env:       map[string]string{"TERM": "xterm-256color"},
			Kadeessh: &asciinemaSSHMetadata{
				User:      user,
				SessionID: sessionID,
			},
		}
		hb, _ := json.Marshal(h)
		body = append(hb, '\n')
		body = append(body, []byte(`[0.1,"o","recovered output"]`+"\n")...)
	}
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatalf("write orphan: %v", err)
	}
	return p
}

func TestRecoverOrphans_UploadsAndRemoves(t *testing.T) {
	dir := t.TempDir()
	storage := newMockStorage()
	orphan := writeOrphanTempFile(t, dir, "99999", "alice", "sidX", nil)

	trueVal := true
	rec := &AsciinemaRecorder{
		storage:        storage,
		logger:         caddy.Log(),
		TempDir:        dir,
		RecoverOrphans: &trueVal,
	}
	rec.recoverOrphanRecordings(context.Background())

	if _, statErr := os.Stat(orphan); !os.IsNotExist(statErr) {
		t.Errorf("orphan temp file should have been removed after upload: %v", statErr)
	}
	if len(storage.data) != 1 {
		t.Fatalf("expected 1 stored recording, got %d", len(storage.data))
	}
	var key string
	for k := range storage.data {
		key = k
	}
	if !strings.Contains(key, "alice-sidX-recovered.cast") {
		t.Errorf("recovered key %q should include user/sessionID and -recovered suffix", key)
	}
}

func TestRecoverOrphans_SkipsCurrentPid(t *testing.T) {
	dir := t.TempDir()
	storage := newMockStorage()
	myPid := strconv.Itoa(os.Getpid())
	live := writeOrphanTempFile(t, dir, myPid, "alice", "sidLive", nil)
	orphan := writeOrphanTempFile(t, dir, "99999", "bob", "sidOrphan", nil)

	trueVal := true
	rec := &AsciinemaRecorder{
		storage:        storage,
		logger:         caddy.Log(),
		TempDir:        dir,
		RecoverOrphans: &trueVal,
	}
	rec.recoverOrphanRecordings(context.Background())

	// Our own temp file must not have been touched.
	if _, err := os.Stat(live); err != nil {
		t.Errorf("current-PID temp file should be preserved: %v", err)
	}
	// The other-PID file should have been uploaded and removed.
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("other-PID temp file should have been recovered and removed: %v", err)
	}
	// Storage should only contain the orphan, not the live file.
	if len(storage.data) != 1 {
		t.Fatalf("expected 1 stored recording, got %d: %v", len(storage.data), storage.data)
	}
	for k := range storage.data {
		if !strings.Contains(k, "bob") {
			t.Errorf("wrong recording uploaded: %s", k)
		}
	}
}

func TestRecoverOrphans_EmptyFileRemoved(t *testing.T) {
	dir := t.TempDir()
	storage := newMockStorage()
	empty := writeOrphanTempFile(t, dir, "77777", "", "", []byte{})

	trueVal := true
	rec := &AsciinemaRecorder{
		storage:        storage,
		logger:         caddy.Log(),
		TempDir:        dir,
		RecoverOrphans: &trueVal,
	}
	rec.recoverOrphanRecordings(context.Background())

	if _, err := os.Stat(empty); !os.IsNotExist(err) {
		t.Errorf("empty temp file should be removed: %v", err)
	}
	if len(storage.data) != 0 {
		t.Errorf("no data should be uploaded for empty file, got %v", storage.data)
	}
}

func TestRecoverOrphans_MalformedFallbackPath(t *testing.T) {
	dir := t.TempDir()
	storage := newMockStorage()
	// A file with junk instead of a header line.
	malformed := writeOrphanTempFile(t, dir, "88888", "", "", []byte("not-json\n[0,\"o\",\"x\"]\n"))

	trueVal := true
	rec := &AsciinemaRecorder{
		storage:        storage,
		logger:         caddy.Log(),
		TempDir:        dir,
		RecoverOrphans: &trueVal,
	}
	rec.recoverOrphanRecordings(context.Background())

	if _, err := os.Stat(malformed); !os.IsNotExist(err) {
		t.Errorf("malformed orphan should still be uploaded and removed: %v", err)
	}
	if len(storage.data) != 1 {
		t.Fatalf("expected 1 stored recording, got %d", len(storage.data))
	}
	for k := range storage.data {
		if !strings.HasPrefix(k, "ssh/recordings/recovered/") {
			t.Errorf("malformed orphan should land in recovered/ fallback, got %s", k)
		}
	}
}

func TestRecoverOrphans_UploadFailurePreservesFile(t *testing.T) {
	dir := t.TempDir()
	storage := &mockStorage{data: map[string][]byte{}, storeErr: errors.New("nope")}
	orphan := writeOrphanTempFile(t, dir, "66666", "alice", "sid1", nil)

	trueVal := true
	rec := &AsciinemaRecorder{
		storage:        storage,
		logger:         caddy.Log(),
		TempDir:        dir,
		RecoverOrphans: &trueVal,
	}
	rec.recoverOrphanRecordings(context.Background())

	if _, err := os.Stat(orphan); err != nil {
		t.Errorf("orphan should be preserved on upload failure: %v", err)
	}
}

func TestRecoverOrphans_IgnoresUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	storage := newMockStorage()
	unrelated := filepath.Join(dir, "some-other-app.log")
	if err := os.WriteFile(unrelated, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write unrelated: %v", err)
	}

	trueVal := true
	rec := &AsciinemaRecorder{
		storage:        storage,
		logger:         caddy.Log(),
		TempDir:        dir,
		RecoverOrphans: &trueVal,
	}
	rec.recoverOrphanRecordings(context.Background())

	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("unrelated file should be untouched: %v", err)
	}
	if len(storage.data) != 0 {
		t.Errorf("no uploads expected, got %v", storage.data)
	}
}

func TestDeriveRecoveredStoragePath(t *testing.T) {
	// Well-formed header with metadata.
	h := asciinemaHeader{
		Version:   2,
		Timestamp: time.Date(2025, 10, 24, 12, 0, 0, 0, time.UTC).Unix(),
		Kadeessh: &asciinemaSSHMetadata{
			User:      "alice",
			SessionID: "abcdef",
		},
	}
	hb, _ := json.Marshal(h)
	got := deriveRecoveredStoragePath(append(hb, '\n'), "fallback.cast")
	want := "ssh/recordings/2025-10-24/alice-abcdef-recovered.cast"
	if got != want {
		t.Errorf("well-formed: got %q, want %q", got, want)
	}

	// No newline at all.
	got = deriveRecoveredStoragePath([]byte("no newline here"), "orphan.cast")
	if got != "ssh/recordings/recovered/orphan.cast" {
		t.Errorf("no newline: got %q", got)
	}

	// Header parseable but no kadeessh block.
	got = deriveRecoveredStoragePath([]byte(`{"version":2}`+"\n"), "bare.cast")
	if got != "ssh/recordings/recovered/bare.cast" {
		t.Errorf("no kadeessh: got %q", got)
	}
}
