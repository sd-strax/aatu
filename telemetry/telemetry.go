// Package telemetry is the Phase A.8 observability layer: structured logging
// (slog), distributed tracing (OpenTelemetry), and metrics (Prometheus). It is
// deliberately export-light at v0 — the OTel tracer provider is configured with
// NO exporter, so spans are created and propagated in-process but not shipped
// anywhere yet. Wiring a real exporter (OTLP) is a v1 concern; the span API is
// live now so instrumentation added across the codebase is not wasted.
//
// Setup installs the global slog logger and the global OTel tracer provider,
// and (optionally) builds a Prometheus registry. Callers thread the returned
// Provider's HTTPMiddleware and MetricsHandler into the HTTP server, and any
// package can emit spans via telemetry.Tracer(name) once Setup has run.
package telemetry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// Config configures the observability layer.
type Config struct {
	// ServiceName labels traces and metrics (e.g. "reckon").
	ServiceName string

	// LogLevel is the minimum slog level: "debug", "info", "warn", "error".
	// Empty defaults to "info".
	LogLevel string

	// LogFormat is "text" or "json". Empty defaults to "text".
	LogFormat string

	// LogDir, when non-empty, enables rolling file logs under it (in addition
	// to stderr). Empty disables file logging.
	LogDir string

	// MetricsEnabled builds a Prometheus registry and enables the /metrics
	// handler. When false, MetricsHandler serves 404 and no metrics are
	// collected.
	MetricsEnabled bool
}

// Provider holds the configured observability primitives and the shutdown
// hooks that release them. One Provider is built per process at startup.
type Provider struct {
	// Logger is the configured structured logger. Also installed as the slog
	// default, so package-level slog.Info(...) calls route through it.
	Logger *slog.Logger

	// Metrics is the Prometheus registry + instruments, or nil when metrics
	// are disabled.
	Metrics *Metrics

	tracer  trace.Tracer
	tp      *sdktrace.TracerProvider
	closers []io.Closer
}

// Setup configures logging, tracing, and metrics, installs the global slog and
// OTel providers, and returns a Provider carrying the HTTP wiring and a
// Shutdown. It is called once, early in process startup.
func Setup(cfg Config) (*Provider, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "reckon"
	}

	logger, closers, err := setupLogging(cfg)
	if err != nil {
		return nil, fmt.Errorf("setup logging: %w", err)
	}
	slog.SetDefault(logger)

	// Tracer provider with NO span processor/exporter (v0: API only). Spans are
	// created and parent/child links are honored in-process; nothing is
	// exported. A v1 OTLP exporter slots in here without touching call sites.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(resource.NewSchemaless(
			attribute.String("service.name", cfg.ServiceName),
		)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	var metrics *Metrics
	if cfg.MetricsEnabled {
		metrics = newMetrics()
	}

	return &Provider{
		Logger:  logger,
		Metrics: metrics,
		tracer:  tp.Tracer("reckon/server"),
		tp:      tp,
		closers: closers,
	}, nil
}

// Shutdown flushes and releases observability resources: the tracer provider
// (any buffered spans) and log file handles. Best-effort — the first error is
// returned but every closer still runs.
func (p *Provider) Shutdown(ctx context.Context) error {
	var firstErr error
	if p.tp != nil {
		if err := p.tp.Shutdown(ctx); err != nil {
			firstErr = fmt.Errorf("tracer provider shutdown: %w", err)
		}
	}
	for _, c := range p.closers {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Tracer returns a named tracer from the global provider. Safe to cache in a
// package var before Setup runs — the global tracer delegates to whatever
// provider Setup installs later.
func Tracer(name string) trace.Tracer { return otel.Tracer(name) }

// DefaultLogDir returns the conventional rolling-log directory under dataDir
// (<dataDir>/logs). Callers pass the result as Config.LogDir.
func DefaultLogDir(dataDir string) string { return filepath.Join(dataDir, "logs") }
