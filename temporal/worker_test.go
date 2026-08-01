package temporal

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"

	"github.com/sd-strax/reckon/internal/branding"
)

// startTestDevServer boots a throwaway Temporal dev server on a free port,
// reusing a stable bin cache so repeated runs don't re-download. Returns the
// frontend host:port; the server is stopped at test cleanup.
func startTestDevServer(t *testing.T) string {
	t.Helper()
	binDir := filepath.Join(os.TempDir(), "reckon-temporal-test-bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin dir: %v", err)
	}
	srv, err := testsuite.StartDevServer(context.Background(), testsuite.DevServerOptions{
		CachedDownload: testsuite.CachedDownload{DestDir: binDir},
		ClientOptions:  &client.Options{Namespace: "default"},
		DBFilename:     filepath.Join(t.TempDir(), "test.sqlite"),
		LogLevel:       "error",
	})
	if err != nil {
		t.Fatalf("start temporal dev server: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	return srv.FrontendHostPort()
}

// TestWorkerPingRoundTrip is the A.7 done-bar proof: a command-path caller
// (Client.Ping) dispatches a workflow, the in-process worker picks it up off
// the task queue, and the result comes back — the full command → Temporal →
// worker → result round trip against a real dev server.
func TestWorkerPingRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test needs the Temporal dev-server binary; skipped in -short")
	}
	ctx := context.Background()
	hostPort := startTestDevServer(t)

	w := NewWorker(WorkerConfig{HostPort: hostPort, Namespace: "default"})
	if err := w.Start(ctx); err != nil {
		t.Fatalf("worker start: %v", err)
	}
	t.Cleanup(func() { _ = w.Stop(ctx) })

	if h := w.Health(ctx); !h.Ready {
		t.Errorf("worker health not ready: %s", h.Message)
	}

	cl, err := NewClient(ClientConfig{HostPort: hostPort, Namespace: "default"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(cl.Close)

	out, err := cl.Ping(ctx, "abc")
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	if out != "pong:abc" {
		t.Errorf("ping result = %q; want %q", out, "pong:abc")
	}

	// The skeleton domain workflows are registered but unimplemented:
	// dispatching one through the real worker returns the non-retryable error,
	// proving both that registration happened on the reckon task queue and that
	// Phase C has a clear, loud TODO.
	raw, err := client.Dial(client.Options{HostPort: hostPort, Namespace: "default"})
	if err != nil {
		t.Fatalf("dial raw client: %v", err)
	}
	defer raw.Close()
	run, err := raw.ExecuteWorkflow(ctx, client.StartWorkflowOptions{TaskQueue: branding.CLI}, WorkflowActionLifecycle)
	if err != nil {
		t.Fatalf("dispatch ActionLifecycle: %v", err)
	}
	if err := run.Get(ctx, nil); err == nil {
		t.Error("ActionLifecycle skeleton returned nil; want an unimplemented error")
	}
}

// TestWorkerHealthBeforeStart: an unstarted worker reports not-ready (so the
// supervisor watcher never treats a dead worker as live), and Stop before Start
// is a no-op. Fast — no dev server.
func TestWorkerHealthBeforeStart(t *testing.T) {
	w := NewWorker(WorkerConfig{HostPort: "localhost:1", Namespace: "default"})
	if h := w.Health(context.Background()); h.Ready {
		t.Errorf("unstarted worker reports ready: %+v", h)
	}
	if err := w.Stop(context.Background()); err != nil {
		t.Errorf("Stop before Start returned error: %v", err)
	}
}

// TestActivityStructsRegisterCleanly: Worker.Start registers the activity
// structs wholesale (RegisterActivity picks up every exported method), and the
// SDK panics at boot on any exported method that isn't a valid activity
// signature — a stray builder/helper method would take the whole stack down.
// The test environment runs the same registry validation, so it fails here in
// the fast suite instead. Fast — no dev server.
func TestActivityStructsRegisterCleanly(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("activity struct has an exported method with a non-activity signature: %v", r)
		}
	}()
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestActivityEnvironment()
	env.RegisterActivity(NewActivities(nil, nil, nil))
	env.RegisterActivity(NewArchiveActivities(nil, nil, ""))
}
