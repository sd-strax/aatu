package aggregate

import (
	"testing"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestHandleEmitsNestedSpans proves the aggregate half of the A.8 trace: Handle
// opens an "aggregate.Handle" span and each event's projection runs under a
// child "aggregate.project" span, correctly nested in one trace. Combined with
// the telemetry HTTP-middleware span, a command flowing HTTP → handler →
// projection produces the single cross-layer trace the A.8 done-bar calls for.
func TestHandleEmitsNestedSpans(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)

	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(sdktrace.NewTracerProvider()) })

	h := newTestHandler()
	aggID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), CreateInvestigation{Title: "INV-TRACE"})

	var handle, project sdktrace.ReadOnlySpan
	for _, s := range sr.Ended() {
		switch s.Name() {
		case "aggregate.Handle":
			handle = s
		case "aggregate.project":
			project = s
		}
	}
	if handle == nil {
		t.Fatal("no aggregate.Handle span recorded")
	}
	if project == nil {
		t.Fatal("no aggregate.project span recorded")
	}
	if project.Parent().SpanID() != handle.SpanContext().SpanID() {
		t.Errorf("aggregate.project parent span = %v; want Handle span %v (not nested in one trace)",
			project.Parent().SpanID(), handle.SpanContext().SpanID())
	}
}
