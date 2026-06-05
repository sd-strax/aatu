package supervisor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"go.temporal.io/sdk/client"
)

// TestTemporalLifecycle exercises the Temporal dev-server component end to end:
// start (downloads CLI on first run), reachable client, clean stop, restart
// against persisted SQLite state.
//
// First-run cost: ~15–20s for the Temporal CLI download.
// Warm: ~3–5s.
// Skipped in short mode.
func TestTemporalLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow Temporal lifecycle test in short mode")
	}

	dir := filepath.Join(t.TempDir(), "temporal")

	cfg := TemporalConfig{
		DataDir:      dir,
		FrontendPort: 17233, // non-default to avoid colliding with a real Temporal
		EnableUI:     false,
		Namespace:    "reckon-test",
	}
	tp := NewTemporal(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if err := tp.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	if h := tp.Health(ctx); !h.Ready {
		t.Errorf("expected ready; got %+v", h)
	}

	// Dial the real Temporal client against the running dev server and run
	// the SDK's gRPC health check — proves the frontend is reachable and
	// serving.
	c, err := client.Dial(client.Options{
		HostPort:  tp.FrontendHostPort(),
		Namespace: "reckon-test",
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := c.CheckHealth(ctx, &client.CheckHealthRequest{}); err != nil {
		t.Errorf("CheckHealth: %v", err)
	}
	c.Close()

	if err := tp.Stop(ctx); err != nil {
		t.Errorf("stop: %v", err)
	}

	// Restart against the same SQLite file; should come up cleanly.
	tp2 := NewTemporal(cfg)
	if err := tp2.Start(ctx); err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		_ = tp2.Stop(stopCtx)
	})

	if h := tp2.Health(ctx); !h.Ready {
		t.Errorf("expected ready after restart; got %+v", h)
	}

	c2, err := client.Dial(client.Options{
		HostPort:  tp2.FrontendHostPort(),
		Namespace: "reckon-test",
	})
	if err != nil {
		t.Fatalf("dial after restart: %v", err)
	}
	defer c2.Close()
	if _, err := c2.CheckHealth(ctx, &client.CheckHealthRequest{}); err != nil {
		t.Errorf("CheckHealth after restart: %v", err)
	}
}
