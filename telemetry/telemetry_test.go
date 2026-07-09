package telemetry

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"WARN":  slog.LevelWarn,
		"error": slog.LevelError,
		"":      slog.LevelInfo,
		"bogus": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %v; want %v", in, got, want)
		}
	}
}

func TestNormalizeRoute(t *testing.T) {
	cases := map[string]string{
		"/api/investigations":     "/api/investigations",
		"/api/investigations/123": "/api/investigations/:id",
		"/api/investigations/3f2504e0-4f89-11d3-9a0c-0305e82c3301": "/api/investigations/:id",
		"/healthz": "/healthz",
		"":         "/",
	}
	for in, want := range cases {
		if got := normalizeRoute(in); got != want {
			t.Errorf("normalizeRoute(%q) = %q; want %q", in, got, want)
		}
	}
}

// TestRotatingWriter forces several rotations and asserts the active file plus
// backups exist and the backup count is capped at maxFiles.
func TestRotatingWriter(t *testing.T) {
	dir := t.TempDir()
	w, err := newRotatingWriter(dir, "test.log", 100, 3)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}
	chunk := bytes.Repeat([]byte("x"), 60)
	for i := 0; i < 8; i++ {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "test.log")); err != nil {
		t.Errorf("active file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "test.log.1")); err != nil {
		t.Errorf("rotated backup .1 missing: %v", err)
	}
	// maxFiles=3, so .4 must never appear.
	if _, err := os.Stat(filepath.Join(dir, "test.log.4")); err == nil {
		t.Error("backup .4 exists; maxFiles=3 should have capped rotation")
	}
}

// TestSetupWritesFileAndMetrics exercises the full Setup: logging to a rolling
// file, the global logger install, and a metrics registry.
func TestSetupWritesFileAndMetrics(t *testing.T) {
	dir := t.TempDir()
	p, err := Setup(Config{
		ServiceName:    "reckon",
		LogLevel:       "debug",
		LogFormat:      "json",
		LogDir:         dir,
		MetricsEnabled: true,
	})
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	slog.Info("hello from test", "k", "v")

	if p.Metrics == nil {
		t.Fatal("metrics enabled but Provider.Metrics is nil")
	}
	data, err := os.ReadFile(filepath.Join(dir, logFileName))
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "hello from test") {
		t.Errorf("log file does not contain the logged line; got:\n%s", data)
	}
}

// TestHTTPMiddlewareRecordsSpanAndMetrics proves the middleware opens a server
// span (with the normalized route and an error status for a 5xx) and increments
// the request counter — the HTTP-layer half of the A.8 done-bar.
func TestHTTPMiddlewareRecordsSpanAndMetrics(t *testing.T) {
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))

	p := &Provider{Metrics: newMetrics(), tracer: tp.Tracer("reckon/server")}
	h := p.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/investigations/3f2504e0-4f89-11d3-9a0c-0305e82c3301", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("recorded %d spans; want 1", len(spans))
	}
	span := spans[0]
	if !strings.Contains(span.Name(), "/api/investigations/:id") {
		t.Errorf("span name %q not normalized to :id", span.Name())
	}
	if span.Status().Code != codes.Error {
		t.Errorf("span status = %v; want Error (503 is 5xx)", span.Status().Code)
	}

	got := testutil.ToFloat64(p.Metrics.HTTPRequests.WithLabelValues(http.MethodGet, "/api/investigations/:id", "503"))
	if got != 1 {
		t.Errorf("request counter = %v; want 1", got)
	}
}

// TestMetricsHandlerExposesText confirms /metrics serves the Prometheus text
// format including a reckon instrument.
func TestMetricsHandlerExposesText(t *testing.T) {
	m := newMetrics()
	m.HTTPRequests.WithLabelValues("GET", "/healthz", "200").Inc()

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	if !strings.Contains(body, "reckon_http_requests_total") {
		t.Errorf("metrics output missing reckon_http_requests_total; got:\n%s", body)
	}
}
