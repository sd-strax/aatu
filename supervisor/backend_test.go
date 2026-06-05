package supervisor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

// makeSupWithStarted is a test helper that installs a set of started
// components on a Supervisor without going through Start. Lets us drive
// handler tests without spinning up real processes.
func makeSupWithStarted(components ...Component) *Supervisor {
	s := New()
	for _, c := range components {
		s.Register(c, RestartOnExit)
	}
	s.mu.Lock()
	s.started = append(s.started, components...)
	s.mu.Unlock()
	return s
}

func TestBackendHandleStatus_AllReady(t *testing.T) {
	a := &fakeComponent{name: "postgres", healthy: true}
	b := &fakeComponent{name: "temporal", healthy: true}
	sup := makeSupWithStarted(a, b)

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
}

func TestBackendHandleStatus_Degraded(t *testing.T) {
	a := &fakeComponent{name: "postgres", healthy: true}
	b := &fakeComponent{name: "temporal", healthy: false}
	sup := makeSupWithStarted(a, b)

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
	if resp.Components["temporal"].Ready {
		t.Errorf("temporal should be not-ready")
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
