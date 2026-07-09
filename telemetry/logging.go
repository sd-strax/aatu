package telemetry

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// logRotateMaxBytes is the size a log file reaches before it is rotated.
// logRotateMaxFiles is how many rotated backups are kept (reckon.log.1 ..
// reckon.log.N). Conservative defaults for a bundled local install; a v1
// deployment shipping to a log aggregator overrides via its own handler.
const (
	logRotateMaxBytes = 10 << 20 // 10 MiB
	logRotateMaxFiles = 5
	logFileName       = "reckon.log"
)

// setupLogging builds the slog logger for cfg and returns it along with any
// closers (the rolling file writer, when file logging is enabled). Output goes
// to stderr always, and additionally to a rolling file under cfg.LogDir when
// set.
func setupLogging(cfg Config) (*slog.Logger, []io.Closer, error) {
	var (
		writers = []io.Writer{os.Stderr}
		closers []io.Closer
	)
	if cfg.LogDir != "" {
		rw, err := newRotatingWriter(cfg.LogDir, logFileName, logRotateMaxBytes, logRotateMaxFiles)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file: %w", err)
		}
		writers = append(writers, rw)
		closers = append(closers, rw)
	}

	out := io.MultiWriter(writers...)
	opts := &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}

	var handler slog.Handler
	switch strings.ToLower(cfg.LogFormat) {
	case "json":
		handler = slog.NewJSONHandler(out, opts)
	default: // "text" and unknown
		handler = slog.NewTextHandler(out, opts)
	}
	return slog.New(handler).With("service", "reckon"), closers, nil
}

// parseLevel maps a level string to slog.Level, defaulting to Info.
func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// rotatingWriter is a minimal size-based rolling file writer: when the active
// file would exceed maxBytes, it is closed, the backups are shifted
// (base.(N-1) → base.N, …, base → base.1), and a fresh base file is opened. It
// is safe for concurrent Write calls (slog handlers may write concurrently).
//
// This is deliberately small — v0 local logging only. A deployment that needs
// time-based rotation, compression, or retention windows ships logs to an
// aggregator instead and does not use this writer.
type rotatingWriter struct {
	dir      string
	base     string
	maxBytes int64
	maxFiles int

	mu   sync.Mutex
	f    *os.File
	size int64
}

func newRotatingWriter(dir, base string, maxBytes int64, maxFiles int) (*rotatingWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	w := &rotatingWriter{dir: dir, base: base, maxBytes: maxBytes, maxFiles: maxFiles}
	if err := w.openActive(); err != nil {
		return nil, err
	}
	return w, nil
}

// openActive opens (append) the base file and records its current size.
func (w *rotatingWriter) openActive() error {
	path := filepath.Join(w.dir, w.base)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f = f
	w.size = info.Size()
	return nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate closes the active file, shifts the backups, and reopens a fresh base.
func (w *rotatingWriter) rotate() error {
	if err := w.f.Close(); err != nil {
		return err
	}
	// Drop the oldest, then shift each backup up by one.
	oldest := filepath.Join(w.dir, fmt.Sprintf("%s.%d", w.base, w.maxFiles))
	_ = os.Remove(oldest)
	for i := w.maxFiles - 1; i >= 1; i-- {
		src := filepath.Join(w.dir, fmt.Sprintf("%s.%d", w.base, i))
		dst := filepath.Join(w.dir, fmt.Sprintf("%s.%d", w.base, i+1))
		_ = os.Rename(src, dst) // absent backups are fine to skip
	}
	_ = os.Rename(filepath.Join(w.dir, w.base), filepath.Join(w.dir, w.base+".1"))
	return w.openActive()
}

// Close closes the active file.
func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
