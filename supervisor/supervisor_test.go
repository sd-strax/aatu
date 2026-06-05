package supervisor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeComponent struct {
	name string

	mu         sync.Mutex
	startCalls int
	stopCalls  int
	healthy    bool
	startErr   error
}

func (f *fakeComponent) Name() string { return f.name }

func (f *fakeComponent) Start(_ context.Context) error {
	f.mu.Lock()
	f.startCalls++
	err := f.startErr
	if err == nil {
		f.healthy = true
	}
	f.mu.Unlock()
	return err
}

func (f *fakeComponent) Stop(_ context.Context) error {
	f.mu.Lock()
	f.stopCalls++
	f.healthy = false
	f.mu.Unlock()
	return nil
}

func (f *fakeComponent) Health(_ context.Context) HealthStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return HealthStatus{Ready: f.healthy}
}

func (f *fakeComponent) setHealthy(b bool) {
	f.mu.Lock()
	f.healthy = b
	f.mu.Unlock()
}

func (f *fakeComponent) setStartErr(e error) {
	f.mu.Lock()
	f.startErr = e
	f.mu.Unlock()
}

func (f *fakeComponent) getStartCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startCalls
}

func (f *fakeComponent) getStopCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopCalls
}

// withFastWatcher temporarily speeds up the supervisor watcher loop so tests
// don't have to wait the production 5s polling interval.
func withFastWatcher(t *testing.T) {
	t.Helper()
	origInterval := watchInterval
	origWindow := watchRestartWindow
	watchInterval = 50 * time.Millisecond
	watchRestartWindow = 30 * time.Second
	t.Cleanup(func() {
		watchInterval = origInterval
		watchRestartWindow = origWindow
	})
}

// withMaxRestarts temporarily lowers the restart budget for tests that
// exercise the escalation path so they don't have to induce three restart
// cycles back-to-back.
func withMaxRestarts(t *testing.T, n int) {
	t.Helper()
	orig := watchMaxRestarts
	watchMaxRestarts = n
	t.Cleanup(func() { watchMaxRestarts = orig })
}

// waitFor polls predicate every 10ms until it returns true or timeout. Fails
// the test if the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, msg string, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("waitFor %q timed out after %v", msg, timeout)
}

func TestSupervisorStartStopOrder(t *testing.T) {
	a := &fakeComponent{name: "a"}
	b := &fakeComponent{name: "b"}
	c := &fakeComponent{name: "c"}

	sup := New()
	sup.Register(a, RestartOnExit)
	sup.Register(b, RestartOnExit)
	sup.Register(c, FatalOnExit)

	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	if a.getStartCalls() != 1 || b.getStartCalls() != 1 || c.getStartCalls() != 1 {
		t.Errorf("expected each start once; got a=%d b=%d c=%d",
			a.getStartCalls(), b.getStartCalls(), c.getStartCalls())
	}

	h := sup.Health(context.Background())
	if !h["a"].Ready || !h["b"].Ready || !h["c"].Ready {
		t.Errorf("expected all healthy; got %v", h)
	}

	if err := sup.Stop(context.Background()); err != nil {
		t.Errorf("stop: %v", err)
	}

	if a.getStopCalls() != 1 || b.getStopCalls() != 1 || c.getStopCalls() != 1 {
		t.Errorf("expected each stop once; got a=%d b=%d c=%d",
			a.getStopCalls(), b.getStopCalls(), c.getStopCalls())
	}
}

func TestSupervisorStartFailureRollback(t *testing.T) {
	a := &fakeComponent{name: "a"}
	b := &fakeComponent{name: "b", startErr: errors.New("boom")}
	c := &fakeComponent{name: "c"}

	sup := New()
	sup.Register(a, RestartOnExit)
	sup.Register(b, RestartOnExit)
	sup.Register(c, RestartOnExit)

	err := sup.Start(context.Background())
	if err == nil {
		t.Fatalf("expected start error")
	}

	if a.getStartCalls() != 1 {
		t.Errorf("a.getStartCalls() = %d; want 1", a.getStartCalls())
	}
	if c.getStartCalls() != 0 {
		t.Errorf("c should not have started; got %d", c.getStartCalls())
	}

	// a was rolled back during the failure cascade
	if a.getStopCalls() != 1 {
		t.Errorf("a.getStopCalls() = %d; want 1 (rollback after b failed)", a.getStopCalls())
	}
}

func TestStopIsBestEffort(t *testing.T) {
	stopErr := errors.New("nope")
	failing := &fakeStopErrComponent{fakeComponent: fakeComponent{name: "failing"}, stopErr: stopErr}
	clean := &fakeComponent{name: "clean"}

	sup := New()
	sup.Register(failing, RestartOnExit)
	sup.Register(clean, RestartOnExit)

	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}

	err := sup.Stop(context.Background())
	if !errors.Is(err, stopErr) {
		t.Errorf("expected stop to surface failing.Stop error; got %v", err)
	}
	// clean.Stop must still have been called (best-effort shutdown)
	if clean.getStopCalls() != 1 {
		t.Errorf("clean.getStopCalls() = %d; want 1 (best-effort even after a failure)", clean.getStopCalls())
	}
}

type fakeStopErrComponent struct {
	fakeComponent
	stopErr error
}

func (f *fakeStopErrComponent) Stop(_ context.Context) error {
	f.mu.Lock()
	f.stopCalls++
	f.healthy = false
	f.mu.Unlock()
	return f.stopErr
}

// --- Run + watcher tests -----------------------------------------------------

func TestRunCancelStopsAllComponents(t *testing.T) {
	withFastWatcher(t)
	a := &fakeComponent{name: "a"}
	b := &fakeComponent{name: "b"}
	sup := New()
	sup.Register(a, RestartOnExit)
	sup.Register(b, FatalOnExit)

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()

	waitFor(t, time.Second, "both started", func() bool {
		return a.getStartCalls() == 1 && b.getStartCalls() == 1
	})

	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run returned error on clean cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	if a.getStopCalls() != 1 || b.getStopCalls() != 1 {
		t.Errorf("expected each stopped once; got a=%d b=%d",
			a.getStopCalls(), b.getStopCalls())
	}
}

func TestRunRestartsUnhealthyComponent(t *testing.T) {
	withFastWatcher(t)
	a := &fakeComponent{name: "a"}
	sup := New()
	sup.Register(a, RestartOnExit)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()

	waitFor(t, time.Second, "initial start", func() bool {
		return a.getStartCalls() == 1
	})

	// Mark unhealthy → watcher detects (2 misses ~ 100ms) → Stop + Start
	a.setHealthy(false)

	waitFor(t, time.Second, "restart issued", func() bool {
		return a.getStartCalls() == 2 && a.getStopCalls() == 1
	})

	cancel()
	<-runDone
}

func TestRunFatalOnExitTerminatesSupervisor(t *testing.T) {
	withFastWatcher(t)
	a := &fakeComponent{name: "a"}
	sup := New()
	sup.Register(a, FatalOnExit)

	ctx := context.Background()
	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(ctx) }()

	waitFor(t, time.Second, "initial start", func() bool {
		return a.getStartCalls() == 1
	})

	// Mark unhealthy → watcher should fatal-cancel and Run returns
	a.setHealthy(false)

	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("expected nil error on fatal-cancel; got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit on FatalOnExit unhealth")
	}

	// Component was Stop'd as part of shutdown
	if a.getStopCalls() != 1 {
		t.Errorf("expected stop after fatal; got %d", a.getStopCalls())
	}
}

func TestRunRestartBudgetEscalates(t *testing.T) {
	withFastWatcher(t)
	withMaxRestarts(t, 2)
	a := &fakeComponent{name: "a"}
	sup := New()
	sup.Register(a, RestartOnExit)

	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(context.Background()) }()

	waitFor(t, time.Second, "initial start", func() bool {
		return a.getStartCalls() == 1
	})

	// Episode 1: unhealthy → restart (start#2). Wait for it.
	a.setHealthy(false)
	waitFor(t, time.Second, "restart #1", func() bool {
		return a.getStartCalls() == 2
	})

	// Episode 2: unhealthy → restart (start#3).
	a.setHealthy(false)
	waitFor(t, time.Second, "restart #2", func() bool {
		return a.getStartCalls() == 3
	})

	// Episode 3: unhealthy. Now len(restartTimes)==2 (which equals
	// watchMaxRestarts) so the watcher escalates instead of restarting again.
	a.setHealthy(false)

	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run returned error on fatal-cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not escalate after budget exhausted; startCalls=%d",
			a.getStartCalls())
	}

	// Should NOT have done a 4th start
	if got := a.getStartCalls(); got > 3 {
		t.Errorf("expected ≤3 starts (budget=2 + initial); got %d", got)
	}
}

func TestRunRestartFailureEscalates(t *testing.T) {
	withFastWatcher(t)
	a := &fakeComponent{name: "a"}
	sup := New()
	sup.Register(a, RestartOnExit)

	runDone := make(chan error, 1)
	go func() { runDone <- sup.Run(context.Background()) }()

	waitFor(t, time.Second, "initial start", func() bool {
		return a.getStartCalls() == 1
	})

	// Make the next Start call fail. The watcher's restart sequence is
	// Stop → Start; if Start returns error, watcher escalates to fatal.
	a.setStartErr(errors.New("doomed"))
	a.setHealthy(false)

	select {
	case err := <-runDone:
		if err != nil {
			t.Errorf("Run returned error on fatal-cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not escalate on restart Start failure")
	}
}
