package supervisor

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Component is one managed dependency or in-process service.
// Implementations must be safe to Start once, Stop once, and accept
// concurrent Health calls.
type Component interface {
	// Name is a stable identifier used for logging and status reporting.
	Name() string

	// Start the component. Returns nil only when the component is ready
	// to serve. Returns an error if startup fails or ctx is cancelled.
	Start(ctx context.Context) error

	// Stop the component gracefully. Should complete within ctx's deadline.
	Stop(ctx context.Context) error

	// Health returns the current readiness/status of the component.
	// Must be safe to call concurrently with Start/Stop.
	Health(ctx context.Context) HealthStatus
}

// HealthStatus is the runtime state of a Component.
type HealthStatus struct {
	Ready   bool
	Message string
}

// RestartPolicy tells the supervisor how to react when a Component exits
// unexpectedly (not via a Stop call).
//
// Today this records intent; the per-component watcher lands in A.2.5.
type RestartPolicy int

const (
	// RestartOnExit attempts to restart the Component up to MaxRestarts times
	// within a sliding window before escalating.
	RestartOnExit RestartPolicy = iota

	// FatalOnExit halts the entire supervisor when this Component exits
	// unexpectedly. Used for components where an unclean exit risks data
	// corruption (Postgres mid-transaction is the canonical case).
	FatalOnExit
)

// Spec wraps a Component with its supervision policy.
type Spec struct {
	Component
	Policy      RestartPolicy
	MaxRestarts int
}

// Supervisor manages the lifecycle of a set of Components.
type Supervisor struct {
	specs   []Spec
	mu      sync.Mutex
	started []Component // for stop ordering
}

// New returns a fresh, empty Supervisor.
func New() *Supervisor {
	return &Supervisor{}
}

// Register adds a Component. Components start in the order they are
// registered and stop in reverse order. Default MaxRestarts is 3.
func (s *Supervisor) Register(c Component, policy RestartPolicy) {
	s.specs = append(s.specs, Spec{Component: c, Policy: policy, MaxRestarts: 3})
}

// Start every registered component in order. On the first failure,
// already-started components are stopped in reverse order before the
// error is returned.
func (s *Supervisor) Start(ctx context.Context) error {
	for _, spec := range s.specs {
		log.Printf("supervisor: starting %s", spec.Name())
		if err := spec.Start(ctx); err != nil {
			log.Printf("supervisor: %s failed to start: %v", spec.Name(), err)
			_ = s.shutdown(ctx)
			return fmt.Errorf("start %s: %w", spec.Name(), err)
		}
		s.mu.Lock()
		s.started = append(s.started, spec.Component)
		s.mu.Unlock()
		log.Printf("supervisor: %s ready", spec.Name())
	}
	return nil
}

// Stop every started component in reverse order. Best-effort: stop errors
// are logged but don't prevent the next component from being stopped. The
// first error encountered (if any) is returned.
func (s *Supervisor) Stop(ctx context.Context) error {
	return s.shutdown(ctx)
}

func (s *Supervisor) shutdown(ctx context.Context) error {
	s.mu.Lock()
	started := s.started
	s.started = nil
	s.mu.Unlock()

	var firstErr error
	for i := len(started) - 1; i >= 0; i-- {
		c := started[i]
		log.Printf("supervisor: stopping %s", c.Name())
		if err := c.Stop(ctx); err != nil {
			log.Printf("supervisor: %s stop error: %v", c.Name(), err)
			if firstErr == nil {
				firstErr = err
			}
		} else {
			log.Printf("supervisor: %s stopped", c.Name())
		}
	}
	return firstErr
}

// Health rolls up the current status of every started Component.
func (s *Supervisor) Health(ctx context.Context) map[string]HealthStatus {
	s.mu.Lock()
	started := append([]Component(nil), s.started...)
	s.mu.Unlock()

	out := make(map[string]HealthStatus, len(started))
	for _, c := range started {
		out[c.Name()] = c.Health(ctx)
	}
	return out
}

// Watcher tuning. Conservative defaults: 5s polling, 2 consecutive misses
// before declaring exit (so a single transient blip doesn't trigger a
// restart cascade), 3 restarts in a rolling 5-minute window before escalating
// to fatal. Aggressive enough to catch real outages, lenient enough not to
// fight with normal startup jitter.
//
// These are vars (not consts) so tests can override them via t.Cleanup.
var (
	watchInterval          = 5 * time.Second
	watchConsecutiveMisses = 2
	watchMaxRestarts       = 3
	watchRestartWindow     = 5 * time.Minute
)

// Run starts every registered component, then supervises them: each
// component is polled for health and restarted (or escalated to fatal-exit)
// per its RestartPolicy. Run blocks until ctx is cancelled OR a FatalOnExit
// component fails OR a RestartOnExit component exhausts its restart budget.
// Then Run stops every component and returns.
//
// This is the typical entry point for a long-running supervisor invocation.
// Calling Start + Stop directly remains valid for tests or for tighter
// external control of the lifecycle.
func (s *Supervisor) Run(ctx context.Context) error {
	if err := s.Start(ctx); err != nil {
		return err
	}

	runCtx, fatalCancel := context.WithCancel(ctx)
	defer fatalCancel()

	var wg sync.WaitGroup
	for _, spec := range s.specs {
		wg.Add(1)
		go func(spec Spec) {
			defer wg.Done()
			s.watch(runCtx, fatalCancel, spec)
		}(spec)
	}

	<-runCtx.Done()
	log.Println("supervisor: run cancelled; awaiting watchers")
	wg.Wait()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopCancel()
	if err := s.Stop(stopCtx); err != nil {
		return fmt.Errorf("supervisor stop: %w", err)
	}
	return nil
}

// watch polls a single Component for health on watchInterval. Two consecutive
// misses count as "unexpected exit"; on exit, the Component's RestartPolicy
// dictates whether the supervisor restarts it or escalates to fatal-cancel.
//
// Exits early on ctx cancellation (i.e., when Run is shutting down) — the
// caller's wg.Wait then knows it's safe to call Stop without races.
func (s *Supervisor) watch(ctx context.Context, fatalCancel context.CancelFunc, spec Spec) {
	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()

	consecutiveMisses := 0
	var restartTimes []time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		h := spec.Health(ctx)
		if h.Ready {
			consecutiveMisses = 0
			continue
		}
		consecutiveMisses++
		if consecutiveMisses < watchConsecutiveMisses {
			continue
		}

		log.Printf("supervisor: %s unhealthy after %d consecutive misses: %s",
			spec.Name(), consecutiveMisses, h.Message)

		switch spec.Policy {
		case FatalOnExit:
			log.Printf("supervisor: %s policy is FatalOnExit — terminating supervisor",
				spec.Name())
			fatalCancel()
			return
		case RestartOnExit:
			restartTimes = trimRestartHistory(restartTimes)
			if len(restartTimes) >= watchMaxRestarts {
				log.Printf("supervisor: %s restarted %d times within %s — escalating to fatal",
					spec.Name(), watchMaxRestarts, watchRestartWindow)
				fatalCancel()
				return
			}
			if ctx.Err() != nil {
				return
			}
			log.Printf("supervisor: restarting %s (attempt %d of %d in the last %s)",
				spec.Name(), len(restartTimes)+1, watchMaxRestarts, watchRestartWindow)
			_ = spec.Stop(ctx)
			if err := spec.Start(ctx); err != nil {
				log.Printf("supervisor: %s restart failed: %v — escalating to fatal",
					spec.Name(), err)
				fatalCancel()
				return
			}
			restartTimes = append(restartTimes, time.Now())
			consecutiveMisses = 0
		}
	}
}

func trimRestartHistory(history []time.Time) []time.Time {
	cutoff := time.Now().Add(-watchRestartWindow)
	out := history[:0]
	for _, t := range history {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}
