package adapterplugin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
)

// Supervision budget (§2): mirror the supervisor's own sliding window — 3
// restarts in 5 minutes — but exhaustion marks the adapter UNHEALTHY rather than
// escalating to fatal. An integration must never take the engine down.
const (
	defaultMaxRestarts   = 3
	defaultRestartWindow = 5 * time.Minute
	handshakeTimeout     = 10 * time.Second
	healthTimeout        = 5 * time.Second
)

// Plugin is the engine-side handle to one out-of-process adapter instance. It
// owns the child process lifecycle: lazy spawn on first demand, the
// initialize/describe/configure handshake (§4), 1:1 invoke/dispatch/health, and
// budgeted-restart supervision (§2). One Plugin is one enablement instance
// (§5 "named instances"); its config and enablement lists live in tenant config.
//
// The read and write facades in facade.go adapt a Plugin onto capability.Adapter
// and action.WriteAdapter; a single Plugin may back both (a class-mcp vendor
// serving read verbs and write ops, §4.2 / 11 §8).
type Plugin struct {
	instance      string // enablement instance name (the tenant-config key)
	installed     Installed
	class         capability.AdapterClass
	config        map[string]any
	engineVersion string
	logger        *slog.Logger

	maxRestarts   int
	restartWindow time.Duration

	mu           sync.Mutex
	proc         *process
	described    *DescribeResult
	restartTimes []time.Time
	// unhealthy latches when the handshake fails or the restart budget is
	// exhausted; it is the terminal state surfaced as an UNHEALTHY adapter
	// (03 §6.3). It clears only on a successful (re)spawn.
	unhealthy    bool
	unhealthyMsg string
}

// process is one live child: its command, the JSON-RPC connection over its
// pipes, and the plumbing to detect its exit.
type process struct {
	cmd        *exec.Cmd
	conn       *conn
	stdin      io.Closer
	done       chan struct{} // closed when the read loop returns (process exited)
	sem        chan struct{} // concurrency gate (declared in initialize; default serial)
	lifeCtx    context.Context
	lifeCancel context.CancelFunc
}

// Option configures a Plugin at construction.
type Option func(*Plugin)

// WithLogger sets the logger adapter stderr and lifecycle events are written to.
func WithLogger(l *slog.Logger) Option {
	return func(p *Plugin) { p.logger = l }
}

// WithRestartBudget overrides the default sliding-window restart budget.
func WithRestartBudget(max int, window time.Duration) Option {
	return func(p *Plugin) { p.maxRestarts, p.restartWindow = max, window }
}

// New builds a Plugin for an installed adapter and its instance config. It does
// NOT spawn — spawning is lazy (§2), on the first Invoke/Dispatch/Health/
// Describe. config carries the instance's validated configuration with any
// x-secret fields as UNRESOLVED references (§4.3).
func New(instance string, installed Installed, config map[string]any, engineVersion string, opts ...Option) (*Plugin, error) {
	class, err := installed.Manifest.AdapterClass()
	if err != nil {
		return nil, err
	}
	p := &Plugin{
		instance:      instance,
		installed:     installed,
		class:         class,
		config:        config,
		engineVersion: engineVersion,
		logger:        slog.Default(),
		maxRestarts:   defaultMaxRestarts,
		restartWindow: defaultRestartWindow,
	}
	for _, o := range opts {
		o(p)
	}
	return p, nil
}

// Instance is the enablement instance name (the tenant-config key).
func (p *Plugin) Instance() string { return p.instance }

// Class is the adapter's class, normalized from the manifest.
func (p *Plugin) Class() capability.AdapterClass { return p.class }

// Describe returns the adapter's self-description (§4.2), spawning and running
// the handshake if needed. Callers reconcile it into the catalog under the
// §4.2 rules (adapter owns capability facts; engine owns tier/reversibility).
func (p *Plugin) Describe(ctx context.Context) (*DescribeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.ensureLocked(ctx); err != nil {
		return nil, err
	}
	return p.described, nil
}

// Invoke runs one read operation (capability.Adapter.Invoke). Failures map onto
// the 03 §6.2 taxonomy as *capability.AdapterError.
func (p *Plugin) Invoke(ctx context.Context, operation string, params map[string]any) (capability.AdapterResponse, error) {
	p.mu.Lock()
	if err := p.ensureLocked(ctx); err != nil {
		p.mu.Unlock()
		// A failed spawn/handshake means the adapter is down, whatever RPC code
		// caused it — UNHEALTHY, never re-classified through an embedded error.
		return capability.AdapterResponse{}, &capability.AdapterError{Class: capability.ErrUnhealthy, Err: err}
	}
	proc := p.proc
	p.mu.Unlock()

	if err := acquire(ctx, proc.sem); err != nil {
		return capability.AdapterResponse{}, readError(err)
	}
	defer release(proc.sem)

	var res invokeResult
	if err := proc.conn.Call(ctx, methodInvoke, InvokeParams{Operation: operation, Params: params}, &res); err != nil {
		return capability.AdapterResponse{}, readError(err)
	}
	return res.toResponse(), nil
}

// Dispatch runs one write operation (action.WriteAdapter.Dispatch). Failures
// map onto the 08 §5 taxonomy as *action.WriteError. A transport failure is
// classified FATAL_ERROR, not retryable: the call may have taken effect and we
// cannot confirm, so the honest-state posture forbids a blind re-attempt.
func (p *Plugin) Dispatch(ctx context.Context, operation string, params map[string]any, idempotencyKey string) (action.WriteResult, error) {
	p.mu.Lock()
	if err := p.ensureLocked(ctx); err != nil {
		p.mu.Unlock()
		// A down adapter never took the write: FATAL_ERROR, no retry.
		return action.WriteResult{}, &action.WriteError{Class: action.WriteFatal, Err: err}
	}
	proc := p.proc
	p.mu.Unlock()

	if err := acquire(ctx, proc.sem); err != nil {
		return action.WriteResult{}, writeError(err)
	}
	defer release(proc.sem)

	var res action.WriteResult
	err := proc.conn.Call(ctx, methodDispatch, DispatchParams{
		Operation:      operation,
		Params:         params,
		IdempotencyKey: idempotencyKey,
	}, &res)
	if err != nil {
		return action.WriteResult{}, writeError(err)
	}
	return res, nil
}

// Health reports current readiness (capability.Adapter.Health). A health probe
// is a valid first demand, so it spawns lazily (§2). A latched-unhealthy or
// unspawnable adapter reports unhealthy with a diagnostic rather than failing.
func (p *Plugin) Health() capability.HealthStatus {
	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()

	p.mu.Lock()
	if err := p.ensureLocked(ctx); err != nil {
		msg := p.unhealthyMsg
		if msg == "" {
			msg = err.Error()
		}
		p.mu.Unlock()
		return capability.HealthStatus{Healthy: false, Message: msg}
	}
	proc := p.proc
	p.mu.Unlock()

	if err := acquire(ctx, proc.sem); err != nil {
		return capability.HealthStatus{Healthy: false, Message: err.Error()}
	}
	defer release(proc.sem)

	var res healthResult
	if err := proc.conn.Call(ctx, methodHealth, struct{}{}, &res); err != nil {
		return capability.HealthStatus{Healthy: false, Message: "health probe failed: " + err.Error()}
	}
	return capability.HealthStatus{Healthy: res.Healthy, Message: res.Message}
}

// Close terminates the child process. It is safe to call more than once.
func (p *Plugin) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked()
}

// ensureLocked guarantees a live, handshaken process, respawning a dead one
// within the restart budget. It must be called with p.mu held. On budget
// exhaustion or handshake failure it latches unhealthy and returns an error.
func (p *Plugin) ensureLocked(ctx context.Context) error {
	// A live process whose read loop is still running is ready.
	dead := false
	if p.proc != nil {
		select {
		case <-p.proc.done:
			// Exited since last use — a (re)spawn from here is a RESTART.
			p.reapLocked()
			dead = true
		default:
			return nil
		}
	}
	if p.unhealthy {
		return fmt.Errorf("adapter %q unhealthy: %s", p.instance, p.unhealthyMsg)
	}
	// The initial spawn (dead == false) never counts against the budget; only a
	// respawn after a death does. maxRestarts respawns are allowed in the
	// window, then the adapter latches UNHEALTHY (§2 — never fatal).
	if dead {
		p.restartTimes = append(trimHistory(p.restartTimes, p.restartWindow), time.Now())
		if len(p.restartTimes) > p.maxRestarts {
			p.latchUnhealthyLocked(fmt.Sprintf("restart budget exhausted (%d in %s)", p.maxRestarts, p.restartWindow))
			return fmt.Errorf("adapter %q unhealthy: %s", p.instance, p.unhealthyMsg)
		}
	}
	return p.spawnLocked(ctx)
}

// reapLocked tears down a dead process (its read loop has already returned).
func (p *Plugin) reapLocked() {
	if p.proc != nil {
		p.proc.lifeCancel()
		_ = p.proc.cmd.Wait()
		p.proc = nil
	}
}

// spawnLocked launches the child, wires its pipes, runs the handshake, and
// records the described capabilities. On any failure it latches unhealthy.
func (p *Plugin) spawnLocked(ctx context.Context) error {
	lifeCtx, lifeCancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(lifeCtx, p.installed.Manifest.Exec[0], p.installed.Manifest.Exec[1:]...)
	cmd.Dir = p.installed.Dir
	// Clean environment: adapters spawn with no credentials (§2). Only PATH and
	// HOME survive so an interpreter/launcher named in exec can be found;
	// secrets reach the adapter as unresolved refs via configure (§4.3).
	cmd.Env = minimalEnv()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		lifeCancel()
		return p.spawnFailed("open stdin", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		lifeCancel()
		return p.spawnFailed("open stdout", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		lifeCancel()
		return p.spawnFailed("open stderr", err)
	}
	if err := cmd.Start(); err != nil {
		lifeCancel()
		return p.spawnFailed("start", err)
	}

	go p.forwardStderr(stderr)

	c := newConn(stdin)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := c.runOn(stdout); err != nil {
			p.logger.Warn("adapter connection ended", "adapter", p.instance, "err", err)
		}
	}()

	proc := &process{
		cmd:        cmd,
		conn:       c,
		stdin:      stdin,
		done:       done,
		sem:        make(chan struct{}, 1),
		lifeCtx:    lifeCtx,
		lifeCancel: lifeCancel,
	}

	if err := p.handshake(ctx, proc); err != nil {
		lifeCancel()
		_ = cmd.Wait()
		return p.spawnFailed("handshake", err)
	}
	p.proc = proc
	p.unhealthy, p.unhealthyMsg = false, ""
	p.logger.Info("adapter ready", "adapter", p.instance, "class", p.class, "version", p.installed.Manifest.Version)
	return nil
}

// handshake runs initialize → describe → configure (§4) under handshakeTimeout,
// sizing the concurrency gate from the adapter's declared parallelism.
func (p *Plugin) handshake(ctx context.Context, proc *process) error {
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()

	var init InitializeResult
	if err := proc.conn.Call(hctx, methodInitialize, InitializeParams{
		EngineProtocolVersions: []int{ProtocolVersion},
		EngineVersion:          p.engineVersion,
	}, &init); err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	if init.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("initialize: adapter negotiated protocol %d, engine speaks %d", init.ProtocolVersion, ProtocolVersion)
	}
	if init.Concurrency > 1 {
		proc.sem = make(chan struct{}, init.Concurrency)
	}

	var desc DescribeResult
	if err := proc.conn.Call(hctx, methodDescribe, struct{}{}, &desc); err != nil {
		return fmt.Errorf("describe: %w", err)
	}
	p.described = &desc

	// configure is the final handshake step; a rejection marks the adapter
	// unhealthy like any health failure (§4.3).
	if err := proc.conn.Call(hctx, methodConfigure, ConfigureParams{Config: p.config}, nil); err != nil {
		return fmt.Errorf("configure: %w", err)
	}
	return nil
}

// spawnFailed latches unhealthy with a spawn-stage diagnostic and returns it.
func (p *Plugin) spawnFailed(stage string, err error) error {
	p.latchUnhealthyLocked(fmt.Sprintf("%s: %v", stage, err))
	return fmt.Errorf("adapter %q: %s: %w", p.instance, stage, err)
}

func (p *Plugin) latchUnhealthyLocked(msg string) {
	p.unhealthy, p.unhealthyMsg = true, msg
	p.logger.Warn("adapter unhealthy", "adapter", p.instance, "reason", msg)
}

func (p *Plugin) stopLocked() {
	if p.proc == nil {
		return
	}
	_ = p.proc.stdin.Close() // half-close invites a clean adapter exit
	p.proc.lifeCancel()
	_ = p.proc.cmd.Wait()
	p.proc = nil
}

// forwardStderr relays an adapter's stderr to the engine log, line by line, so
// adapter diagnostics are visible without polluting the JSON-RPC channel.
func (p *Plugin) forwardStderr(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			p.logger.Debug("adapter stderr", "adapter", p.instance, "line", line)
		}
	}
}

func minimalEnv() []string {
	env := make([]string, 0, 2)
	if path := os.Getenv("PATH"); path != "" {
		env = append(env, "PATH="+path)
	}
	if home := os.Getenv("HOME"); home != "" {
		env = append(env, "HOME="+home)
	}
	return env
}

// trimHistory drops restart timestamps older than the window.
func trimHistory(times []time.Time, window time.Duration) []time.Time {
	cutoff := time.Now().Add(-window)
	out := times[:0:0]
	for _, t := range times {
		if t.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

// acquire takes the concurrency gate, respecting ctx cancellation.
func acquire(ctx context.Context, sem chan struct{}) error {
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func release(sem chan struct{}) { <-sem }

// readError maps a transport/RPC error onto the read taxonomy (03 §6.2). A
// classified adapter error uses its class; an unclassified one defaults to
// FALLTHROUGH (the resolver's safe default); a transport failure means the
// adapter is down → UNHEALTHY.
func readError(err error) error {
	var ce *callError
	if errors.As(err, &ce) {
		switch decodeClass(ce.Data) {
		case string(capability.ErrRetry):
			return &capability.AdapterError{Class: capability.ErrRetry, Err: ce}
		case string(capability.ErrUnhealthy):
			return &capability.AdapterError{Class: capability.ErrUnhealthy, Err: ce}
		case string(capability.ErrFatal):
			return &capability.AdapterError{Class: capability.ErrFatal, Err: ce}
		default:
			return &capability.AdapterError{Class: capability.ErrFallthrough, Err: ce}
		}
	}
	return &capability.AdapterError{Class: capability.ErrUnhealthy, Err: err}
}

// writeError maps a transport/RPC error onto the write taxonomy (08 §5). An
// unclassified or transport failure defaults to FATAL_ERROR: never auto-retry
// an ambiguous write (honest-state, no-fall-through).
func writeError(err error) error {
	var ce *callError
	if errors.As(err, &ce) {
		if decodeClass(ce.Data) == string(action.WriteRetryable) {
			return &action.WriteError{Class: action.WriteRetryable, Err: ce}
		}
		return &action.WriteError{Class: action.WriteFatal, Err: ce}
	}
	return &action.WriteError{Class: action.WriteFatal, Err: err}
}

func decodeClass(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	var d errorData
	if err := json.Unmarshal(data, &d); err != nil {
		return ""
	}
	return d.Class
}
