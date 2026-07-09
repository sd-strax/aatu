package temporal

import (
	"context"
	"fmt"
	"sync"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/supervisor"
)

// WorkerConfig configures the in-process Temporal worker.
type WorkerConfig struct {
	// HostPort is the Temporal frontend gRPC address, e.g. "localhost:7233".
	HostPort string

	// Namespace is the Temporal namespace to register on. Default "default".
	Namespace string

	// TaskQueue is the queue this worker polls. Default branding.CLI ("reckon")
	// per design/05-component-architecture.md §3.3. Per-tenant task queues are a
	// tenancy-module concern (paid); OSS runs the single shared queue.
	TaskQueue string
}

// Worker is the in-process Temporal worker component. It runs in the same OS
// process as the backend — there is no separate worker binary (05 §3.3) — and
// satisfies supervisor.Component so the supervisor manages its lifecycle
// alongside the bundled subprocesses.
//
// At Phase A.7 it registers the OSS workflow inventory with empty bodies (they
// fail fast with a non-retryable "unimplemented" error until Phase C fills
// them) plus the trivial Ping workflow that proves the command → Temporal →
// worker → result round trip. See workflows.go for the inventory.
type Worker struct {
	cfg WorkerConfig

	mu      sync.Mutex // guards client/worker/started; Health runs concurrently with watcher Stop/Start
	client  client.Client
	worker  worker.Worker
	started bool
}

// NewWorker constructs the worker component (not yet started). Defaults:
// Namespace="default", TaskQueue=branding.CLI.
func NewWorker(cfg WorkerConfig) *Worker {
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	if cfg.TaskQueue == "" {
		cfg.TaskQueue = branding.CLI
	}
	return &Worker{cfg: cfg}
}

// Name returns "temporal-worker" — distinct from the "temporal" server
// component so /status reports the two separately.
func (w *Worker) Name() string { return "temporal-worker" }

// Start dials the Temporal frontend, verifies it is reachable, creates a worker
// on the configured task queue, registers the workflow inventory, and begins
// polling. Start returns only once the worker is polling (or an error). On any
// failure it closes the client it opened so a restart starts clean.
func (w *Worker) Start(ctx context.Context) error {
	c, err := client.Dial(client.Options{
		HostPort:  w.cfg.HostPort,
		Namespace: w.cfg.Namespace,
	})
	if err != nil {
		return fmt.Errorf("dial temporal %s: %w", w.cfg.HostPort, err)
	}
	if _, err := c.CheckHealth(ctx, &client.CheckHealthRequest{}); err != nil {
		c.Close()
		return fmt.Errorf("temporal health check: %w", err)
	}

	wk := worker.New(c, w.cfg.TaskQueue, worker.Options{})
	registerWorkflows(wk)

	if err := wk.Start(); err != nil {
		c.Close()
		return fmt.Errorf("start worker on task queue %q: %w", w.cfg.TaskQueue, err)
	}

	w.mu.Lock()
	w.client = c
	w.worker = wk
	w.started = true
	w.mu.Unlock()
	return nil
}

// Stop halts the worker's pollers and closes the Temporal client. Idempotent —
// multiple calls (or a call before Start) return nil.
func (w *Worker) Stop(_ context.Context) error {
	w.mu.Lock()
	wk := w.worker
	c := w.client
	w.worker = nil
	w.client = nil
	w.started = false
	w.mu.Unlock()

	if wk != nil {
		wk.Stop()
	}
	if c != nil {
		c.Close()
	}
	return nil
}

// Health reports whether the worker is polling and its Temporal connection is
// live. A dropped frontend must surface here or the watcher's RestartOnExit
// policy never fires — "started once" is not liveness.
func (w *Worker) Health(ctx context.Context) supervisor.HealthStatus {
	w.mu.Lock()
	c := w.client
	started := w.started
	w.mu.Unlock()

	if !started || c == nil {
		return supervisor.HealthStatus{Ready: false, Message: "not started"}
	}
	if _, err := c.CheckHealth(ctx, &client.CheckHealthRequest{}); err != nil {
		return supervisor.HealthStatus{Ready: false, Message: fmt.Sprintf("temporal unreachable: %v", err)}
	}
	return supervisor.HealthStatus{
		Ready:   true,
		Message: fmt.Sprintf("polling task queue %q (namespace %s)", w.cfg.TaskQueue, w.cfg.Namespace),
	}
}
