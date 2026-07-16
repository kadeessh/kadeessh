package actors

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/kadeessh/kadeessh/internal/session"
	"github.com/kadeessh/kadeessh/internal/ssh"
	"go.uber.org/zap"
)

const (
	// defaultFlushInterval controls how often the temp-file write buffer is
	// flushed and fsynced during a session. Since flushing is now a local
	// filesystem operation rather than an upload, this can be aggressive.
	defaultFlushInterval = time.Second
	storeTimeout         = 30 * time.Second
	maxFilenamePartLen   = 64
	// tempFilePrefix is the shared prefix for in-progress recording temp
	// files. A PID segment follows so that at startup we can distinguish
	// files owned by this process (still live) from orphans left by a
	// previous crashed process.
	tempFilePrefix = "kadeessh-record-"
)

// tempFilePattern returns the pattern passed to os.CreateTemp for new
// in-progress recording files. The PID prefix lets recoverOrphans safely
// skip files this process still has open across a config reload.
func tempFilePattern() string {
	return fmt.Sprintf("%s%d-*.cast", tempFilePrefix, os.Getpid())
}

var unsafeFilenameChar = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func init() {
	caddy.RegisterModule(AsciinemaRecorder{})
}

// AsciinemaRecorder wraps another handler to record the SSH session output
// in asciinema cast v2 format, which is then saved in Caddy storage.
// Only output is captured for security reasons (no input/keystrokes).
//
// EXPERIMENTAL: this module is under active development. Its configuration
// surface (option names, defaults, on-disk temp-file layout, recovered
// storage key naming) and log field shapes may change without notice.
// Do not rely on any of these for long-term automation yet.
type AsciinemaRecorder struct {
	// The wrapped handler that will handle the actual session
	HandlerRaw json.RawMessage `json:"handler,omitempty" caddy:"namespace=ssh.actors inline_key=action"`

	// The Caddy storage module to save recordings. If absent or null, the default storage is used.
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`

	// Optional: Maximum recording size in bytes. Zero means no limit.
	// Default: 0 (unlimited)
	MaxSize int64 `json:"max_size,omitempty"`

	// Optional: Maximum recording duration. Zero means no limit.
	// Default: 0 (unlimited)
	MaxDuration caddy.Duration `json:"max_duration,omitempty"`

	// Optional: Behavior when recording fails. Options: "continue" or "reject".
	// "continue": Continue session without recording (default)
	// "reject": Reject the session if recording fails
	// Default: "continue"
	OnRecordingError string `json:"on_recording_error,omitempty"`

	// Optional: Include session metadata in the recording header.
	// This includes username, session ID, client IP, timestamp, and terminal size.
	// Default: true
	IncludeMetadata *bool `json:"include_metadata,omitempty"`

	// Optional: How often the in-progress recording is flushed and fsynced
	// to its local temp file. Bounds data loss on crash to roughly one
	// interval. A negative value disables periodic fsync; the OS may still
	// hold un-persisted writes in the page cache until session close.
	FlushInterval caddy.Duration `json:"flush_interval,omitempty"`

	// Optional: Directory for in-progress recording temp files. Defaults to
	// the OS temp dir. On graceful session close the temp file is uploaded
	// to storage and deleted; on crash the temp file remains and can be
	// recovered manually.
	TempDir string `json:"temp_dir,omitempty"`

	// Optional: Automatically upload orphan recordings found in TempDir at
	// startup (leftovers from a previous crashed process). Files created by
	// the current process are always skipped. Default: true.
	RecoverOrphans *bool `json:"recover_orphans,omitempty"`

	handler session.Handler
	storage certmagic.Storage
	logger  *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (a AsciinemaRecorder) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.actors.asciinema_recorder",
		New: func() caddy.Module {
			return new(AsciinemaRecorder)
		},
	}
}

// Provision sets up the AsciinemaRecorder module.
func (a *AsciinemaRecorder) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger(a)

	// Load the wrapped handler
	if len(a.HandlerRaw) == 0 {
		return fmt.Errorf("handler is required for asciinema_recorder")
	}

	val, err := ctx.LoadModule(a, "HandlerRaw")
	if err != nil {
		return fmt.Errorf("loading handler module: %v", err)
	}
	a.handler = val.(session.Handler)

	// Load storage module
	if a.StorageRaw != nil {
		val, err := ctx.LoadModule(a, "StorageRaw")
		if err != nil {
			return fmt.Errorf("loading storage module: %v", err)
		}
		st, err := val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return fmt.Errorf("creating storage configuration: %v", err)
		}
		a.storage = st
	}
	if a.storage == nil {
		a.storage = ctx.Storage()
	}

	// Set defaults
	if a.OnRecordingError == "" {
		a.OnRecordingError = "continue"
	}

	// Validate OnRecordingError
	if a.OnRecordingError != "continue" && a.OnRecordingError != "reject" {
		return fmt.Errorf("on_recording_error must be 'continue' or 'reject', got: %s", a.OnRecordingError)
	}

	// Default include_metadata to true
	if a.IncludeMetadata == nil {
		includeMetadata := true
		a.IncludeMetadata = &includeMetadata
	}

	// Default flush interval; a negative value disables periodic flushing.
	if a.FlushInterval == 0 {
		a.FlushInterval = caddy.Duration(defaultFlushInterval)
	}

	// Default temp directory.
	if a.TempDir == "" {
		a.TempDir = os.TempDir()
	}
	if info, err := os.Stat(a.TempDir); err != nil {
		return fmt.Errorf("temp_dir %q not accessible: %w", a.TempDir, err)
	} else if !info.IsDir() {
		return fmt.Errorf("temp_dir %q is not a directory", a.TempDir)
	}

	// Default recover_orphans to true.
	if a.RecoverOrphans == nil {
		trueVal := true
		a.RecoverOrphans = &trueVal
	}
	if *a.RecoverOrphans {
		// Run asynchronously so slow storage doesn't delay Caddy startup.
		go a.recoverOrphanRecordings(ctx)
	}

	return nil
}

// Handle wraps the underlying handler and records the session output.
func (a AsciinemaRecorder) Handle(sess session.Session) error {
	sessionID := getSessionID(sess.Context())

	recorder, err := a.newRecorder(sess)
	if err != nil {
		a.logger.Error(
			"failed to create recorder",
			zap.Error(err),
			zap.String("user", sess.User()),
			zap.String("remote_ip", sess.RemoteAddr().String()),
			zap.String("session_id", sessionID),
		)
		if a.OnRecordingError == "reject" {
			return fmt.Errorf("recording initialization failed: %w", err)
		}
		a.logger.Warn(
			"continuing session without recording",
			zap.String("user", sess.User()),
			zap.String("remote_ip", sess.RemoteAddr().String()),
			zap.String("session_id", sessionID),
		)
		return a.handler.Handle(sess)
	}

	recorder.startFlusher()

	wrappedSession := &recordingSession{
		Session:  sess,
		recorder: recorder,
	}

	err = a.handler.Handle(wrappedSession)

	if closeErr := recorder.Close(); closeErr != nil {
		a.logger.Error(
			"failed to save recording",
			zap.Error(closeErr),
			zap.String("user", sess.User()),
			zap.String("remote_ip", sess.RemoteAddr().String()),
			zap.String("session_id", sessionID),
		)
	} else {
		a.logger.Info(
			"session recording completed",
			zap.String("user", sess.User()),
			zap.String("remote_ip", sess.RemoteAddr().String()),
			zap.String("session_id", sessionID),
			zap.String("path", recorder.storagePath),
			zap.Int64("size", recorder.totalSize),
			zap.Bool("truncated", recorder.wasTruncated()),
		)
	}

	return err
}

// newRecorder creates a new asciinema recorder for the session.
func (a *AsciinemaRecorder) newRecorder(sess session.Session) (*asciinemaRecorder, error) {
	ctx := sess.Context()

	now := time.Now()
	dateStr := now.Format("2006-01-02")
	sessionID := getSessionID(ctx)

	// Sanitize both parts of the filename: username is client-controlled and
	// sessionID is a hex string but is defensively sanitized as well.
	safeUser := sanitizeFilenamePart(sess.User())
	safeSessionID := sanitizeFilenamePart(sessionID)

	// Use path (forward-slash) for storage keys — storage backends treat
	// keys as opaque paths, not host-filesystem paths.
	basePath := path.Join("ssh", "recordings", dateStr)
	storagePath := path.Join(basePath, fmt.Sprintf("%s-%s.cast", safeUser, safeSessionID))

	// If a recording already exists at this key (e.g. leftover from a crashed
	// session with a colliding ID), append a nanosecond suffix so we never
	// silently overwrite prior audit data.
	{
		probeCtx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		if a.storage.Exists(probeCtx, storagePath) {
			storagePath = path.Join(basePath,
				fmt.Sprintf("%s-%s-%d.cast", safeUser, safeSessionID, now.UnixNano()))
		}
		cancel()
	}

	// Determine terminal type: prefer the client-requested TERM from the PTY
	// request, fall back to a sensible default.
	term := "xterm-256color"
	width, height := 80, 24
	var ptyReq ssh.Pty
	var hasPty bool
	if p, _, ok := sess.Pty(); ok {
		hasPty = true
		ptyReq = p
		if p.Term != "" {
			term = p.Term
		}
		if p.Window.Width > 0 {
			width = p.Window.Width
		}
		if p.Window.Height > 0 {
			height = p.Window.Height
		}
	}

	header := asciinemaHeader{
		Version:   2,
		Width:     width,
		Height:    height,
		Timestamp: now.Unix(),
		Env: map[string]string{
			"TERM": term,
		},
	}

	if *a.IncludeMetadata {
		header.Title = fmt.Sprintf(
			"%s@%s (session: %s)",
			sess.User(),
			sess.RemoteAddr().String(),
			sessionID,
		)
		meta := &asciinemaSSHMetadata{
			User:      sess.User(),
			Client:    sess.RemoteAddr().String(),
			Server:    sess.LocalAddr().String(),
			SessionID: sessionID,
		}
		if clientVersion, ok := ctx.Value(ssh.ContextKeyClientVersion).(string); ok {
			meta.ClientVersion = clientVersion
		}
		if hasPty {
			meta.PtyTerm = ptyReq.Term
		}
		header.Kadeessh = meta
	}

	rec := &asciinemaRecorder{
		storage:       a.storage,
		storagePath:   storagePath,
		header:        header,
		startTime:     now,
		maxSize:       a.MaxSize,
		maxDuration:   time.Duration(a.MaxDuration),
		flushInterval: time.Duration(a.FlushInterval),
		logger:        a.logger,
	}
	if err := rec.openTempFile(a.TempDir); err != nil {
		return nil, fmt.Errorf("opening recording temp file: %w", err)
	}
	a.logger.Debug(
		"recording started",
		zap.String("user", sess.User()),
		zap.String("session_id", sessionID),
		zap.String("temp_path", rec.tempPath),
		zap.String("storage_path", storagePath),
	)
	return rec, nil
}

// openTempFile creates the local temp file that backs the in-progress
// recording, writes the cast v2 header line, and installs a buffered writer.
// The file is only read back and uploaded to storage at Close.
func (r *asciinemaRecorder) openTempFile(dir string) error {
	f, err := os.CreateTemp(dir, tempFilePattern())
	if err != nil {
		return err
	}
	r.tempFile = f
	r.tempPath = f.Name()
	r.tempBuf = bufio.NewWriter(f)

	headerJSON, err := json.Marshal(r.header)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(r.tempPath)
		r.tempFile, r.tempBuf, r.tempPath = nil, nil, ""
		return fmt.Errorf("marshal header: %w", err)
	}
	if _, err := r.tempBuf.Write(headerJSON); err != nil {
		_ = f.Close()
		_ = os.Remove(r.tempPath)
		r.tempFile, r.tempBuf, r.tempPath = nil, nil, ""
		return fmt.Errorf("write header: %w", err)
	}
	if err := r.tempBuf.WriteByte('\n'); err != nil {
		_ = f.Close()
		_ = os.Remove(r.tempPath)
		r.tempFile, r.tempBuf, r.tempPath = nil, nil, ""
		return err
	}
	return nil
}

// sanitizeFilenamePart makes a client-supplied string safe to embed in a
// storage key: strips path separators, dot-segments, control characters, and
// caps length. Never returns an empty string.
func sanitizeFilenamePart(s string) string {
	s = strings.TrimSpace(s)
	s = unsafeFilenameChar.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return "unknown"
	}
	if len(s) > maxFilenamePartLen {
		s = s[:maxFilenamePartLen]
	}
	return s
}

// getSessionID extracts the session ID from the context, or returns "unknown" if not found.
func getSessionID(ctx context.Context) string {
	if sessionID, ok := ctx.Value(ssh.ContextKeySessionID).(string); ok {
		return sessionID
	}
	return "unknown"
}

// recoverOrphanRecordings scans TempDir for cast files left from previous
// crashed processes and uploads them to storage. Files created by the
// current process are skipped so a config reload does not steal in-progress
// recordings from live sessions. Failures are logged but do not fail
// startup.
func (a *AsciinemaRecorder) recoverOrphanRecordings(ctx context.Context) {
	entries, err := os.ReadDir(a.TempDir)
	if err != nil {
		a.logger.Warn(
			"could not scan temp dir for orphan recordings",
			zap.String("temp_dir", a.TempDir),
			zap.Error(err),
		)
		return
	}
	myPid := strconv.Itoa(os.Getpid())
	var recovered, failed int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, tempFilePrefix) || !strings.HasSuffix(name, ".cast") {
			continue
		}
		// Filename format: kadeessh-record-<pid>-<random>.cast
		rest := strings.TrimPrefix(name, tempFilePrefix)
		dash := strings.IndexByte(rest, '-')
		if dash <= 0 {
			// Malformed name (e.g. older format). Skip to avoid data loss.
			continue
		}
		if rest[:dash] == myPid {
			continue
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		p := filepath.Join(a.TempDir, name)
		if err := a.recoverOne(ctx, p); err != nil {
			failed++
			a.logger.Warn(
				"orphan recording recovery failed; temp file left in place",
				zap.String("temp_path", p),
				zap.Error(err),
			)
			continue
		}
		recovered++
	}
	if recovered > 0 || failed > 0 {
		a.logger.Info(
			"orphan recording scan complete",
			zap.String("temp_dir", a.TempDir),
			zap.Int("recovered", recovered),
			zap.Int("failed", failed),
		)
	}
}

// recoverOne uploads a single orphan temp file to storage. On success the
// temp file is removed; on failure the temp file is preserved.
func (a *AsciinemaRecorder) recoverOne(ctx context.Context, tempPath string) error {
	data, err := os.ReadFile(tempPath)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if len(data) == 0 {
		// Empty file (crash before header was written). Safe to remove.
		_ = os.Remove(tempPath)
		return nil
	}

	storagePath := deriveRecoveredStoragePath(data, filepath.Base(tempPath))

	probeCtx, cancel := context.WithTimeout(ctx, storeTimeout)
	if a.storage.Exists(probeCtx, storagePath) {
		base := strings.TrimSuffix(storagePath, ".cast")
		storagePath = fmt.Sprintf("%s-%d.cast", base, time.Now().UnixNano())
	}
	cancel()

	storeCtx, cancel := context.WithTimeout(ctx, storeTimeout)
	defer cancel()
	if err := a.storage.Store(storeCtx, storagePath, data); err != nil {
		return fmt.Errorf("store to %s: %w", storagePath, err)
	}

	a.logger.Info(
		"recovered orphan recording",
		zap.String("temp_path", tempPath),
		zap.String("storage_path", storagePath),
		zap.Int("size", len(data)),
	)
	if err := os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
		a.logger.Warn(
			"could not delete temp file after successful recovery upload",
			zap.String("temp_path", tempPath),
			zap.Error(err),
		)
	}
	return nil
}

// deriveRecoveredStoragePath reconstructs the intended storage key for a
// recovered recording by reading its header. If the header cannot be parsed
// or lacks the required fields, a fallback path under
// `ssh/recordings/recovered/` is returned so no data is lost.
func deriveRecoveredStoragePath(data []byte, fallbackName string) string {
	fallback := path.Join("ssh", "recordings", "recovered", fallbackName)
	nl := bytes.IndexByte(data, '\n')
	if nl <= 0 {
		return fallback
	}
	var h asciinemaHeader
	if err := json.Unmarshal(data[:nl], &h); err != nil {
		return fallback
	}
	if h.Kadeessh == nil || h.Kadeessh.User == "" || h.Kadeessh.SessionID == "" {
		return fallback
	}
	date := time.Now().UTC().Format("2006-01-02")
	if h.Timestamp > 0 {
		date = time.Unix(h.Timestamp, 0).UTC().Format("2006-01-02")
	}
	user := sanitizeFilenamePart(h.Kadeessh.User)
	sid := sanitizeFilenamePart(h.Kadeessh.SessionID)
	return path.Join("ssh", "recordings", date, fmt.Sprintf("%s-%s-recovered.cast", user, sid))
}

// asciinemaHeader represents the header of an asciinema v2 recording.
// SSH-specific metadata lives in the tool-scoped `kadeessh` field rather
// than in `env`, which per the cast v2 spec is reserved for terminal
// environment variables (TERM, SHELL). Unknown top-level fields are
// ignored by conforming players.
type asciinemaHeader struct {
	Version   int                   `json:"version"`
	Width     int                   `json:"width"`
	Height    int                   `json:"height"`
	Timestamp int64                 `json:"timestamp"`
	Env       map[string]string     `json:"env,omitempty"`
	Title     string                `json:"title,omitempty"`
	Kadeessh  *asciinemaSSHMetadata `json:"kadeessh,omitempty"`
}

// asciinemaSSHMetadata carries SSH-connection metadata that is not a
// terminal environment variable.
type asciinemaSSHMetadata struct {
	User          string `json:"user,omitempty"`
	Client        string `json:"client,omitempty"`
	Server        string `json:"server,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
	PtyTerm       string `json:"pty_term,omitempty"`
}

// asciinemaRecorder handles the actual recording logic. Events are streamed
// to a local temp file for durability and only read back into memory once at
// session close to be uploaded through the storage interface.
type asciinemaRecorder struct {
	storage       certmagic.Storage
	storagePath   string
	tempPath      string
	tempFile      *os.File
	tempBuf       *bufio.Writer
	header        asciinemaHeader
	startTime     time.Time
	maxSize       int64
	maxDuration   time.Duration
	flushInterval time.Duration
	logger        *zap.Logger

	mu        sync.Mutex
	totalSize int64
	closed    bool
	truncated bool

	stopFlusher chan struct{}
	flusherDone chan struct{}
}

// startFlusher launches a background goroutine that periodically flushes
// the buffered writer and fsyncs the backing temp file. This bounds data
// loss on crash to roughly one flush interval.
func (r *asciinemaRecorder) startFlusher() {
	if r.flushInterval <= 0 || r.tempFile == nil {
		return
	}
	r.stopFlusher = make(chan struct{})
	r.flusherDone = make(chan struct{})
	go func() {
		defer close(r.flusherDone)
		ticker := time.NewTicker(r.flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stopFlusher:
				return
			case <-ticker.C:
				if err := r.syncTempFile(); err != nil {
					r.logger.Warn(
						"periodic fsync failed",
						zap.String("temp_path", r.tempPath),
						zap.Error(err),
					)
				}
			}
		}
	}()
}

// syncTempFile flushes any buffered event data and calls fsync on the
// backing file. Safe to call from any goroutine.
func (r *asciinemaRecorder) syncTempFile() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.tempFile == nil {
		return nil
	}
	if err := r.tempBuf.Flush(); err != nil {
		return err
	}
	return r.tempFile.Sync()
}

// appendEventLocked marshals and appends a single cast event to the backing
// temp file. Returns false on write failure. Caller must hold r.mu.
func (r *asciinemaRecorder) appendEventLocked(event []interface{}) bool {
	b, err := json.Marshal(event)
	if err != nil {
		r.logger.Error("failed to marshal event", zap.Error(err))
		return false
	}
	if _, err := r.tempBuf.Write(b); err != nil {
		r.logger.Error("failed to write event to temp file", zap.Error(err))
		return false
	}
	if err := r.tempBuf.WriteByte('\n'); err != nil {
		r.logger.Error("failed to write event separator", zap.Error(err))
		return false
	}
	r.totalSize += int64(len(b)) + 1
	return true
}

// markTruncatedLocked emits a marker event indicating the recording was
// truncated, then flips the truncated flag so subsequent events are dropped.
// Caller must hold r.mu.
func (r *asciinemaRecorder) markTruncatedLocked(reason string) {
	if r.truncated {
		return
	}
	elapsed := time.Since(r.startTime).Seconds()
	r.appendEventLocked([]interface{}{elapsed, "m", "kadeessh: recording truncated (" + reason + ")"})
	r.truncated = true
	r.logger.Warn(
		"recording truncated",
		zap.String("reason", reason),
		zap.String("path", r.storagePath),
		zap.Int64("size", r.totalSize),
	)
}

// wasTruncated reports whether the recording hit a size or duration limit.
func (r *asciinemaRecorder) wasTruncated() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.truncated
}

// Write captures output data and appends it to the recording buffer.
func (r *asciinemaRecorder) Write(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return 0, fmt.Errorf("recorder is closed")
	}
	if r.truncated {
		return len(p), nil
	}

	if r.maxSize > 0 && r.totalSize+int64(len(p)) > r.maxSize {
		r.markTruncatedLocked("max_size")
		return len(p), nil
	}
	if r.maxDuration > 0 && time.Since(r.startTime) > r.maxDuration {
		r.markTruncatedLocked("max_duration")
		return len(p), nil
	}

	elapsed := time.Since(r.startTime).Seconds()
	r.appendEventLocked([]interface{}{elapsed, "o", string(p)})
	return len(p), nil
}

// WriteResize records a PTY resize event in asciinema cast v2 "r" format.
func (r *asciinemaRecorder) WriteResize(width, height int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.truncated {
		return
	}
	elapsed := time.Since(r.startTime).Seconds()
	r.appendEventLocked([]interface{}{elapsed, "r", fmt.Sprintf("%dx%d", width, height)})
}

// Close stops periodic flushing, uploads the recording from its temp file
// to storage, and removes the temp file on success. On upload failure the
// temp file is preserved for manual recovery and its path is logged.
func (r *asciinemaRecorder) Close() error {
	if r.stopFlusher != nil {
		close(r.stopFlusher)
		<-r.flusherDone
		r.stopFlusher = nil
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true

	if r.tempFile == nil {
		r.mu.Unlock()
		return nil
	}

	// Flush + fsync + close the temp file before reading it back.
	flushErr := r.tempBuf.Flush()
	syncErr := r.tempFile.Sync()
	closeErr := r.tempFile.Close()
	tempPath := r.tempPath
	totalSize := r.totalSize
	r.tempFile = nil
	r.tempBuf = nil
	r.mu.Unlock()

	if flushErr != nil {
		r.logger.Warn("flushing temp file", zap.String("temp_path", tempPath), zap.Error(flushErr))
	}
	if syncErr != nil {
		r.logger.Warn("syncing temp file", zap.String("temp_path", tempPath), zap.Error(syncErr))
	}
	if closeErr != nil {
		r.logger.Warn("closing temp file", zap.String("temp_path", tempPath), zap.Error(closeErr))
	}

	payload, err := os.ReadFile(tempPath)
	if err != nil {
		return fmt.Errorf("reading temp file %s: %w", tempPath, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := r.storage.Store(ctx, r.storagePath, payload); err != nil {
		// Preserve the temp file so an operator can recover the recording.
		r.logger.Error(
			"recording upload failed; temp file preserved for manual recovery",
			zap.String("temp_path", tempPath),
			zap.String("storage_path", r.storagePath),
			zap.Error(err),
		)
		return fmt.Errorf("failed to store recording (temp file kept at %s): %w", tempPath, err)
	}

	if err := os.Remove(tempPath); err != nil && !os.IsNotExist(err) {
		r.logger.Warn(
			"could not delete temp file after successful upload",
			zap.String("temp_path", tempPath),
			zap.Error(err),
		)
	}

	r.logger.Info(
		"recording saved",
		zap.String("path", r.storagePath),
		zap.Int64("size", int64(len(payload))),
		zap.Int64("event_bytes", totalSize),
		zap.Duration("duration", time.Since(r.startTime)),
	)
	return nil
}

// recordingSession wraps a session to intercept Write calls for recording.
type recordingSession struct {
	session.Session
	recorder *asciinemaRecorder

	ptyOnce sync.Once
	ptyReq  ssh.Pty
	ptyCh   <-chan ssh.Window
	ptyOK   bool
}

// Write intercepts writes to capture output for recording.
func (rs *recordingSession) Write(p []byte) (n int, err error) {
	_, _ = rs.recorder.Write(p)
	return rs.Session.Write(p)
}

// Stderr wraps the stderr stream for recording.
func (rs *recordingSession) Stderr() io.ReadWriter {
	stderr := rs.Session.Stderr()
	return &recordingReadWriter{
		ReadWriter: stderr,
		recorder:   rs.recorder,
	}
}

// Pty returns the underlying PTY info but with a fan-out window-change
// channel so the recorder can capture resize events without stealing them
// from the actual session handler.
func (rs *recordingSession) Pty() (ssh.Pty, <-chan ssh.Window, bool) {
	rs.ptyOnce.Do(func() {
		origPty, origCh, ok := rs.Session.Pty()
		rs.ptyReq = origPty
		rs.ptyOK = ok
		if !ok || origCh == nil {
			rs.ptyCh = origCh
			return
		}
		forwarded := make(chan ssh.Window, 1)
		rs.ptyCh = forwarded
		done := rs.Session.Context().Done()
		go func() {
			defer close(forwarded)
			for win := range origCh {
				rs.recorder.WriteResize(win.Width, win.Height)
				select {
				case forwarded <- win:
				case <-done:
					return
				}
			}
		}()
	})
	return rs.ptyReq, rs.ptyCh, rs.ptyOK
}

// recordingReadWriter wraps a ReadWriter to capture writes.
type recordingReadWriter struct {
	io.ReadWriter
	recorder *asciinemaRecorder
}

// Write intercepts writes to stderr for recording.
func (rw *recordingReadWriter) Write(p []byte) (n int, err error) {
	_, _ = rw.recorder.Write(p)
	return rw.ReadWriter.Write(p)
}

// Interface guards
var (
	_ caddy.Module      = (*AsciinemaRecorder)(nil)
	_ caddy.Provisioner = (*AsciinemaRecorder)(nil)
	_ session.Handler   = (*AsciinemaRecorder)(nil)
)
