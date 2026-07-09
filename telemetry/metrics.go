package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics owns a private Prometheus registry (not the global default registry —
// so tests and multiple processes don't collide) plus the reckon instruments.
// The registry pre-registers Go runtime and process collectors so /metrics
// carries the standard baseline out of the box.
type Metrics struct {
	registry *prometheus.Registry

	// HTTPRequests counts backend HTTP requests by method, normalized route,
	// and status code.
	HTTPRequests *prometheus.CounterVec

	// HTTPDuration observes request handling latency in seconds by method and
	// normalized route.
	HTTPDuration *prometheus.HistogramVec
}

// newMetrics builds the registry and instruments. Called by Setup when metrics
// are enabled.
func newMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	httpRequests := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "reckon_http_requests_total",
			Help: "Total backend HTTP requests by method, route, and status code.",
		},
		[]string{"method", "route", "status"},
	)
	httpDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "reckon_http_request_duration_seconds",
			Help:    "Backend HTTP request handling latency in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "route"},
	)
	reg.MustRegister(httpRequests, httpDuration)

	return &Metrics{registry: reg, HTTPRequests: httpRequests, HTTPDuration: httpDuration}
}

// Handler returns the HTTP handler serving this registry in the Prometheus text
// exposition format. Mounted at /metrics by the backend.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}
