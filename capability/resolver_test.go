package capability

import (
	"context"
	"testing"
	"time"
)

// stubAdapter is a configurable Adapter for resolver tests.
type stubAdapter struct {
	name    string
	healthy bool
	resp    AdapterResponse
	err     error
	calls   int
}

func (s *stubAdapter) Name() string                  { return s.name }
func (s *stubAdapter) Class() AdapterClass           { return ClassCustom }
func (s *stubAdapter) SupportedOperations() []string { return []string{"op"} }
func (s *stubAdapter) Health() HealthStatus          { return HealthStatus{Healthy: s.healthy} }
func (s *stubAdapter) Invoke(_ context.Context, _ string, _ map[string]any) (AdapterResponse, error) {
	s.calls++
	return s.resp, s.err
}

func stubAuthResponse() AdapterResponse {
	return AdapterResponse{SourceTool: "stub", Events: []OcsfPayload{{
		ClassUID:  3002,
		ClassName: "Authentication",
		Time:      time.Date(2026, 4, 20, 14, 0, 0, 0, time.UTC),
		Raw: map[string]any{
			"class_uid":    3002,
			"actor":        map[string]any{"user": map[string]any{"name": "jdoe", "domain": "CONTOSO"}},
			"dst_endpoint": map[string]any{"hostname": "H1", "domain": "CONTOSO"},
		},
	}}}
}

func healthyStub(name string) *stubAdapter {
	return &stubAdapter{name: name, healthy: true, resp: stubAuthResponse()}
}

func newResolver(bindings map[string][]Binding, adapters map[string]Adapter) *Resolver {
	return NewResolver(TenantContext{Name: "t"}, bindings, adapters, testRegistry())
}

// TestResolveEndToEndFixture: the fixture adapter through the resolver yields
// COMPLETE with normalized ObservedData and entities.
func TestResolveEndToEndFixture(t *testing.T) {
	a := newTestFixture(t, twoLogonsPlusOther)
	res := newResolver(
		map[string][]Binding{
			"enumerate_logons": {{
				Adapter: "fixture", Operation: "replay", Priority: 100,
				Params: map[string]any{
					"target":  map[string]any{"hostname": "${entity.host.hostname}"},
					"outcome": "SUCCESS",
				},
			}},
		},
		map[string]Adapter{"fixture": a},
	)
	out, err := res.Resolve(context.Background(), "enumerate_logons", CallInput{
		Entity: map[string]any{"host": map[string]any{"hostname": "WIN-FILE01"}},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out.Coverage != CoverageComplete {
		t.Errorf("coverage = %q; want COMPLETE", out.Coverage)
	}
	if len(out.ObservedDataRefs) != 2 {
		t.Errorf("observed_data_refs = %d; want 2", len(out.ObservedDataRefs))
	}
	if len(out.EntityRefs) == 0 {
		t.Error("no entity_refs produced")
	}
}

// TestResolvePriorityStopsAtFirstSuccess: the higher-priority binding is chosen
// and lower-priority bindings are not invoked (non-fan-out).
func TestResolvePriorityStopsAtFirstSuccess(t *testing.T) {
	high, low := healthyStub("high"), healthyStub("low")
	res := newResolver(
		map[string][]Binding{"v": {
			{Adapter: "low", Operation: "op", Priority: 10},
			{Adapter: "high", Operation: "op", Priority: 100},
		}},
		map[string]Adapter{"high": high, "low": low},
	)
	out, err := res.Resolve(context.Background(), "v", CallInput{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Coverage != CoverageComplete {
		t.Errorf("coverage = %q; want COMPLETE", out.Coverage)
	}
	if high.calls != 1 || low.calls != 0 {
		t.Errorf("calls: high=%d low=%d; want 1 and 0", high.calls, low.calls)
	}
}

// TestResolveCoverageClasses exercises the §6.1 classification.
func TestResolveCoverageClasses(t *testing.T) {
	t.Run("unavailable_tenant_no_binding", func(t *testing.T) {
		res := newResolver(map[string][]Binding{}, map[string]Adapter{})
		out, _ := res.Resolve(context.Background(), "missing", CallInput{})
		if out.Coverage != CoverageUnavailableTenant {
			t.Errorf("coverage = %q; want UNAVAILABLE_TENANT", out.Coverage)
		}
	})

	t.Run("unavailable_tenant_not_applicable", func(t *testing.T) {
		res := newResolver(
			map[string][]Binding{"v": {{Adapter: "s", Operation: "op", Priority: 1,
				Params: map[string]any{"id": "${entity.host.external_id}"}}}},
			map[string]Adapter{"s": healthyStub("s")},
		)
		out, _ := res.Resolve(context.Background(), "v", CallInput{Entity: map[string]any{"host": map[string]any{}}})
		if out.Coverage != CoverageUnavailableTenant {
			t.Errorf("coverage = %q; want UNAVAILABLE_TENANT (not applicable)", out.Coverage)
		}
	})

	t.Run("unavailable_transient_unhealthy", func(t *testing.T) {
		down := &stubAdapter{name: "s", healthy: false}
		res := newResolver(
			map[string][]Binding{"v": {{Adapter: "s", Operation: "op", Priority: 1}}},
			map[string]Adapter{"s": down},
		)
		out, _ := res.Resolve(context.Background(), "v", CallInput{})
		if out.Coverage != CoverageUnavailableTransient {
			t.Errorf("coverage = %q; want UNAVAILABLE_TRANSIENT", out.Coverage)
		}
	})

	t.Run("unavailable_transient_invoke_unhealthy", func(t *testing.T) {
		// Adapter passes the health pre-check but Invoke reveals it is
		// unhealthy: still TRANSIENT (recoverable), never UNAVAILABLE_TENANT
		// (structural) — the binding WAS applicable.
		flaky := &stubAdapter{name: "s", healthy: true, err: adapterErrorf(ErrUnhealthy, "auth expired")}
		res := newResolver(
			map[string][]Binding{"v": {{Adapter: "s", Operation: "op", Priority: 1}}},
			map[string]Adapter{"s": flaky},
		)
		out, _ := res.Resolve(context.Background(), "v", CallInput{})
		if out.Coverage != CoverageUnavailableTransient {
			t.Errorf("coverage = %q; want UNAVAILABLE_TRANSIENT", out.Coverage)
		}
	})

	t.Run("failed_call_errors", func(t *testing.T) {
		bad := &stubAdapter{name: "s", healthy: true, err: adapterErrorf(ErrFallthrough, "no data")}
		res := newResolver(
			map[string][]Binding{"v": {{Adapter: "s", Operation: "op", Priority: 1}}},
			map[string]Adapter{"s": bad},
		)
		out, _ := res.Resolve(context.Background(), "v", CallInput{})
		if out.Coverage != CoverageFailed {
			t.Errorf("coverage = %q; want FAILED", out.Coverage)
		}
	})
}

// TestResolveFanout: fan-out bindings all contribute; a mixed outcome is PARTIAL.
func TestResolveFanout(t *testing.T) {
	good := healthyStub("good")
	bad := &stubAdapter{name: "bad", healthy: true, err: adapterErrorf(ErrRetry, "rate limited")}
	res := newResolver(
		map[string][]Binding{"pivot": {
			{Adapter: "good", Operation: "op", Priority: 100, FanOut: true},
			{Adapter: "bad", Operation: "op", Priority: 90, FanOut: true},
		}},
		map[string]Adapter{"good": good, "bad": bad},
	)
	out, err := res.Resolve(context.Background(), "pivot", CallInput{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Coverage != CoveragePartial {
		t.Errorf("coverage = %q; want PARTIAL", out.Coverage)
	}
	if good.calls != 1 || bad.calls != 1 {
		t.Errorf("fan-out should invoke both: good=%d bad=%d", good.calls, bad.calls)
	}
}

// TestResolveFatalPropagates: a FATAL adapter error aborts the call.
func TestResolveFatalPropagates(t *testing.T) {
	boom := &stubAdapter{name: "s", healthy: true, err: adapterErrorf(ErrFatal, "invariant violated")}
	res := newResolver(
		map[string][]Binding{"v": {{Adapter: "s", Operation: "op", Priority: 1}}},
		map[string]Adapter{"s": boom},
	)
	if _, err := res.Resolve(context.Background(), "v", CallInput{}); err == nil {
		t.Error("FATAL error did not propagate")
	}
}

// TestValidateBindings rejects an unknown transform at load time.
func TestValidateBindings(t *testing.T) {
	err := ValidateBindings(map[string][]Binding{
		"v": {{Adapter: "s", Params: map[string]any{"x": "${entity.a | bogus}"}}},
	})
	if err == nil {
		t.Error("ValidateBindings accepted an unknown transform")
	}
}
