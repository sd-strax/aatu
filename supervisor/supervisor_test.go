package supervisor

import (
	"context"
	"errors"
	"testing"
)

type fakeComponent struct {
	name       string
	startCalls int
	stopCalls  int
	healthy    bool
	startErr   error
}

func (f *fakeComponent) Name() string { return f.name }

func (f *fakeComponent) Start(_ context.Context) error {
	f.startCalls++
	if f.startErr != nil {
		return f.startErr
	}
	f.healthy = true
	return nil
}

func (f *fakeComponent) Stop(_ context.Context) error {
	f.stopCalls++
	f.healthy = false
	return nil
}

func (f *fakeComponent) Health(_ context.Context) HealthStatus {
	return HealthStatus{Ready: f.healthy}
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

	if a.startCalls != 1 || b.startCalls != 1 || c.startCalls != 1 {
		t.Errorf("expected each start once; got a=%d b=%d c=%d",
			a.startCalls, b.startCalls, c.startCalls)
	}

	h := sup.Health(context.Background())
	if !h["a"].Ready || !h["b"].Ready || !h["c"].Ready {
		t.Errorf("expected all healthy; got %v", h)
	}

	if err := sup.Stop(context.Background()); err != nil {
		t.Errorf("stop: %v", err)
	}

	if a.stopCalls != 1 || b.stopCalls != 1 || c.stopCalls != 1 {
		t.Errorf("expected each stop once; got a=%d b=%d c=%d",
			a.stopCalls, b.stopCalls, c.stopCalls)
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

	if a.startCalls != 1 {
		t.Errorf("a.startCalls = %d; want 1", a.startCalls)
	}
	if c.startCalls != 0 {
		t.Errorf("c should not have started; got %d", c.startCalls)
	}

	// a was rolled back during the failure cascade
	if a.stopCalls != 1 {
		t.Errorf("a.stopCalls = %d; want 1 (rollback after b failed)", a.stopCalls)
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
	if clean.stopCalls != 1 {
		t.Errorf("clean.stopCalls = %d; want 1 (best-effort even after a failure)", clean.stopCalls)
	}
}

type fakeStopErrComponent struct {
	fakeComponent
	stopErr error
}

func (f *fakeStopErrComponent) Stop(_ context.Context) error {
	f.stopCalls++
	f.healthy = false
	return f.stopErr
}
