package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sd-strax/reckon/supervisor"
)

// fakeComponent is a tiny supervisor.Component that returns whatever
// readiness we configure. Start/Stop are no-ops; Health is the test surface.
// Same shape as the one inside the supervisor package, copied here so server
// tests don't depend on supervisor's test helpers.
type fakeComponent struct {
	name    string
	healthy bool
	msg     string
}

func (f *fakeComponent) Name() string                  { return f.name }
func (f *fakeComponent) Start(_ context.Context) error { return nil }
func (f *fakeComponent) Stop(_ context.Context) error  { return nil }
func (f *fakeComponent) Health(_ context.Context) supervisor.HealthStatus {
	return supervisor.HealthStatus{Ready: f.healthy, Message: f.msg}
}

// makeSupWithStarted registers the given components and runs sup.Start so
// they land in the "started" set that Health iterates over.
func makeSupWithStarted(t *testing.T, components ...supervisor.Component) *supervisor.Supervisor {
	t.Helper()
	s := supervisor.New()
	for _, c := range components {
		s.Register(c, supervisor.RestartOnExit)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("supervisor.Start: %v", err)
	}
	return s
}

func TestBackendHandleHealthz(t *testing.T) {
	b := &Backend{}
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	b.handleHealthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ok") {
		t.Errorf("body = %q; want to contain \"ok\"", w.Body.String())
	}
}

func TestBackendHandleStatus_AllReady(t *testing.T) {
	sup := makeSupWithStarted(t,
		&fakeComponent{name: "postgres", healthy: true, msg: "listening on :5435"},
		&fakeComponent{name: "temporal", healthy: true, msg: "frontend localhost:7233"},
	)
	backend := &Backend{sup: sup}
	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	backend.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
	var resp StatusResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Overall != "ok" {
		t.Errorf("overall = %q; want \"ok\"", resp.Overall)
	}
	if len(resp.Components) != 2 {
		t.Errorf("components count = %d; want 2", len(resp.Components))
	}
	if !resp.Components["postgres"].Ready {
		t.Errorf("postgres not ready in response: %+v", resp.Components["postgres"])
	}
	// The workbench version handshake (design/13 §2) pins on this.
	if resp.APIVersion != APIVersion {
		t.Errorf("api_version = %d; want %d", resp.APIVersion, APIVersion)
	}
}

func TestBackendHandleStatus_Degraded(t *testing.T) {
	sup := makeSupWithStarted(t,
		&fakeComponent{name: "postgres", healthy: true},
		&fakeComponent{name: "temporal", healthy: false},
	)
	backend := &Backend{sup: sup}
	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	backend.handleStatus(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d; want 503 for degraded", w.Code)
	}
	var resp StatusResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Overall != "degraded" {
		t.Errorf("overall = %q; want \"degraded\"", resp.Overall)
	}
}

func TestBackendHealth_BeforeStart(t *testing.T) {
	b := &Backend{cfg: BackendConfig{HTTPPort: 9999}}
	h := b.Health(context.Background())
	if h.Ready {
		t.Errorf("expected not-ready before Start; got %+v", h)
	}
	if !strings.Contains(h.Message, "not started") {
		t.Errorf("message = %q; want to mention \"not started\"", h.Message)
	}
}

func TestBackendName(t *testing.T) {
	b := NewBackend(BackendConfig{}, nil)
	if b.Name() != "backend" {
		t.Errorf("Name = %q; want \"backend\"", b.Name())
	}
	if b.cfg.HTTPPort != 8080 {
		t.Errorf("default HTTPPort = %d; want 8080", b.cfg.HTTPPort)
	}
}
