package telemetry

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
)

// httpTracer returns the tracer for server-side HTTP spans: the provider's own
// tracer (sourced from the tracer provider Setup built) when available, else
// the global tracer. Using the provider-local tracer keeps spans flowing
// through the exact provider Setup configured, independent of global-provider
// rebinding.
func (p *Provider) httpTracer() trace.Tracer {
	if p != nil && p.tracer != nil {
		return p.tracer
	}
	return Tracer("reckon/server")
}

// HTTPMiddleware wraps an http.Handler with a server span (the root of each
// request's trace) and, when metrics are enabled, request-count and latency
// instrumentation. It is the outermost layer of the backend router, so a
// command that flows HTTP → aggregate handler → projector produces one trace
// spanning all three (the A.8 done-bar).
//
// A nil Provider (or one built with metrics disabled) still traces; it simply
// records no metrics.
func (p *Provider) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := normalizeRoute(r.URL.Path)
		ctx, span := p.httpTracer().Start(r.Context(), "HTTP "+r.Method+" "+route,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPRequestMethodKey.String(r.Method),
				semconv.URLPath(r.URL.Path),
			),
		)
		defer span.End()

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r.WithContext(ctx))
		elapsed := time.Since(start)

		span.SetAttributes(semconv.HTTPResponseStatusCode(rec.status))
		if rec.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(rec.status))
		}

		if p != nil && p.Metrics != nil {
			p.Metrics.HTTPRequests.WithLabelValues(r.Method, route, strconv.Itoa(rec.status)).Inc()
			p.Metrics.HTTPDuration.WithLabelValues(r.Method, route).Observe(elapsed.Seconds())
		}
	})
}

// statusRecorder captures the response status code for tracing/metrics without
// altering the response.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wroteHeader = true // an implicit 200 if WriteHeader was never called
	return r.ResponseWriter.Write(b)
}

// normalizeRoute collapses high-cardinality path segments (UUIDs, numeric ids)
// to ":id" so the metrics route label and span name stay bounded — otherwise
// every investigation id would mint its own time series.
func normalizeRoute(path string) string {
	if path == "" {
		return "/"
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if isIDSegment(s) {
			segs[i] = ":id"
		}
	}
	return strings.Join(segs, "/")
}

// isIDSegment reports whether a path segment looks like a resource id (a UUID
// or an all-digits value) rather than a fixed route component.
func isIDSegment(s string) bool {
	if s == "" {
		return false
	}
	if _, err := strconv.Atoi(s); err == nil {
		return true
	}
	// UUID shape: 8-4-4-4-12 hex with dashes.
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}
	return false
}
