package adapterplugin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
)

// echoBin is the compiled reckon-adapter-echo, built once for the whole package.
var echoBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "adapterplugin-echo")
	if err != nil {
		panic(err)
	}
	echoBin = filepath.Join(dir, "reckon-adapter-echo")
	build := exec.Command("go", "build", "-o", echoBin, "github.com/sd-strax/reckon/cmd/reckon-adapter-echo")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic("build echo adapter: " + err.Error())
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// silentLogger keeps adapter stderr and lifecycle noise out of test output.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newEchoPlugin builds a Plugin backed by the compiled echo adapter. Extra opts
// append after the silent logger.
func newEchoPlugin(t *testing.T, config map[string]any, opts ...Option) *Plugin {
	t.Helper()
	man := Manifest{
		ManifestVersion:  1,
		Name:             "echo",
		Version:          "0.0.1",
		ProtocolVersions: []int{1},
		Class:            "CUSTOM",
		Exec:             []string{echoBin},
	}
	installed := Installed{Dir: filepath.Dir(echoBin), Manifest: man}
	opts = append([]Option{WithLogger(silentLogger())}, opts...)
	p, err := New("echo", installed, config, "test-engine", opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestHandshakeAndDescribe(t *testing.T) {
	p := newEchoPlugin(t, nil)
	desc, err := p.Describe(context.Background())
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if len(desc.Verbs) != 1 || desc.Verbs[0].Verb != "get_host_context" {
		t.Fatalf("verbs = %+v, want get_host_context", desc.Verbs)
	}
	if len(desc.ActionTypes) != 1 || desc.ActionTypes[0].ActionType != "host.isolate" {
		t.Fatalf("action_types = %+v, want host.isolate", desc.ActionTypes)
	}
	if len(desc.Operations) != 2 {
		t.Fatalf("operations = %+v, want 2", desc.Operations)
	}
}

func TestInvokeEchoesOCSF(t *testing.T) {
	p := newEchoPlugin(t, nil)
	resp, err := p.Invoke(context.Background(), "get_host_context", map[string]any{"host": "WIN-1"})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if resp.SourceTool != "echo:get_host_context" {
		t.Fatalf("source_tool = %q", resp.SourceTool)
	}
	if len(resp.Events) != 1 || resp.Events[0].ClassUID != 3002 {
		t.Fatalf("events = %+v, want one class 3002", resp.Events)
	}
}

func TestInvokeErrorClassified(t *testing.T) {
	p := newEchoPlugin(t, nil)
	_, err := p.Invoke(context.Background(), "boom_fallthrough", nil)
	var ae *capability.AdapterError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want *capability.AdapterError", err)
	}
	if ae.Class != capability.ErrFallthrough {
		t.Fatalf("class = %q, want FALLTHROUGH", ae.Class)
	}
}

func TestDispatchSucceeds(t *testing.T) {
	p := newEchoPlugin(t, nil)
	res, err := p.Dispatch(context.Background(), "host.isolate", map[string]any{"device": "abc"}, "idem-1")
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if res.FinalOutcome != action.OutcomeSucceeded {
		t.Fatalf("outcome = %q, want SUCCEEDED", res.FinalOutcome)
	}
	if res.AdapterRequestID != "echo-idem-1" {
		t.Fatalf("adapter_request_id = %q", res.AdapterRequestID)
	}
}

func TestDispatchErrorClassified(t *testing.T) {
	p := newEchoPlugin(t, nil)
	_, err := p.Dispatch(context.Background(), "boom_fatal", nil, "idem-2")
	var we *action.WriteError
	if !errors.As(err, &we) {
		t.Fatalf("err = %v, want *action.WriteError", err)
	}
	if we.Class != action.WriteFatal {
		t.Fatalf("class = %q, want FATAL_ERROR", we.Class)
	}
}

func TestHealthReady(t *testing.T) {
	p := newEchoPlugin(t, nil)
	if h := p.Health(); !h.Healthy {
		t.Fatalf("health = %+v, want healthy", h)
	}
}

func TestConfigureRejectionIsUnhealthy(t *testing.T) {
	p := newEchoPlugin(t, map[string]any{"reject": true})
	// A rejected configure fails the handshake → the adapter is UNHEALTHY, and
	// an invoke against it surfaces that rather than dispatching.
	_, err := p.Invoke(context.Background(), "get_host_context", nil)
	var ae *capability.AdapterError
	if !errors.As(err, &ae) || ae.Class != capability.ErrUnhealthy {
		t.Fatalf("err = %v, want UNHEALTHY AdapterError", err)
	}
	if h := p.Health(); h.Healthy {
		t.Fatalf("health = %+v, want unhealthy", h)
	}
}

func TestCrashRespawns(t *testing.T) {
	p := newEchoPlugin(t, nil)
	// Prime the process.
	if _, err := p.Invoke(context.Background(), "get_host_context", nil); err != nil {
		t.Fatalf("first invoke: %v", err)
	}
	// Crash it: the adapter exits without replying, so this call errors.
	if _, err := p.Invoke(context.Background(), "crash", nil); err == nil {
		t.Fatal("crash invoke: want error, got nil")
	}
	// Give the read loop a moment to observe EOF and close `done`.
	waitProcExit(t, p)
	// The next call respawns within budget and succeeds.
	if _, err := p.Invoke(context.Background(), "get_host_context", nil); err != nil {
		t.Fatalf("post-crash invoke: %v", err)
	}
}

func TestRestartBudgetExhausts(t *testing.T) {
	p := newEchoPlugin(t, nil, WithRestartBudget(1, time.Minute))
	if _, err := p.Invoke(context.Background(), "get_host_context", nil); err != nil {
		t.Fatalf("prime: %v", err)
	}
	// First crash: one respawn is allowed.
	_, _ = p.Invoke(context.Background(), "crash", nil)
	waitProcExit(t, p)
	if _, err := p.Invoke(context.Background(), "get_host_context", nil); err != nil {
		t.Fatalf("respawn 1: %v", err)
	}
	// Second crash: budget (1) is now spent — the next demand refuses.
	_, _ = p.Invoke(context.Background(), "crash", nil)
	waitProcExit(t, p)
	_, err := p.Invoke(context.Background(), "get_host_context", nil)
	var ae *capability.AdapterError
	if !errors.As(err, &ae) || ae.Class != capability.ErrUnhealthy {
		t.Fatalf("err = %v, want UNHEALTHY after budget exhaustion", err)
	}
}

// waitProcExit blocks briefly until the plugin's current process read loop has
// observed the crash, so the subsequent ensure sees a dead proc deterministically.
func waitProcExit(t *testing.T, p *Plugin) {
	t.Helper()
	p.mu.Lock()
	proc := p.proc
	p.mu.Unlock()
	if proc == nil {
		return
	}
	select {
	case <-proc.done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for adapter process to exit")
	}
}
