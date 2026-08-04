package adapterplugin

import (
	"context"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
)

// The facades adapt a live Plugin onto the two in-tree semantic contracts so an
// out-of-process adapter is indistinguishable from an in-tree one at the
// resolver (03 §5.3 "Either way, dispatch is uniform"). A single Plugin may back
// both facades — a class-mcp vendor serving read verbs and write ops describes
// both surfaces (§4.2 / 11 §8), and the runtime constructs whichever facades the
// enablement lists ask for.
//
// The supported-operation lists are captured at wiring time from the enabled
// subset of `describe` output, so Name/Class/SupportedOperations stay cheap and
// synchronous (no spawn per call). Invoke/Dispatch/Health delegate to the
// Plugin, which spawns lazily on first demand.

// ReadAdapter presents a Plugin as a capability.Adapter.
type ReadAdapter struct {
	p   *Plugin
	ops []string
}

// NewReadAdapter builds the read facade for a plugin, exposing only the enabled
// operations named in ops (03 §5.3).
func NewReadAdapter(p *Plugin, ops []string) *ReadAdapter {
	return &ReadAdapter{p: p, ops: append([]string(nil), ops...)}
}

func (r *ReadAdapter) Name() string                    { return r.p.Instance() }
func (r *ReadAdapter) Class() capability.AdapterClass  { return r.p.Class() }
func (r *ReadAdapter) SupportedOperations() []string   { return append([]string(nil), r.ops...) }
func (r *ReadAdapter) Health() capability.HealthStatus { return r.p.Health() }

func (r *ReadAdapter) Invoke(ctx context.Context, operation string, params map[string]any) (capability.AdapterResponse, error) {
	return r.p.Invoke(ctx, operation, params)
}

// Compile-time assertion that ReadAdapter satisfies the read contract.
var _ capability.Adapter = (*ReadAdapter)(nil)

// WriteAdapter presents a Plugin as an action.WriteAdapter.
type WriteAdapter struct {
	p   *Plugin
	ops []string
}

// NewWriteAdapter builds the write facade for a plugin, exposing only the
// enabled action operations named in ops (08 §5).
func NewWriteAdapter(p *Plugin, ops []string) *WriteAdapter {
	return &WriteAdapter{p: p, ops: append([]string(nil), ops...)}
}

func (w *WriteAdapter) Name() string                    { return w.p.Instance() }
func (w *WriteAdapter) Class() capability.AdapterClass  { return w.p.Class() }
func (w *WriteAdapter) SupportedActionOps() []string    { return append([]string(nil), w.ops...) }
func (w *WriteAdapter) Health() capability.HealthStatus { return w.p.Health() }

func (w *WriteAdapter) Dispatch(ctx context.Context, operation string, params map[string]any, idempotencyKey string) (action.WriteResult, error) {
	return w.p.Dispatch(ctx, operation, params, idempotencyKey)
}

// Compile-time assertion that WriteAdapter satisfies the write contract.
var _ action.WriteAdapter = (*WriteAdapter)(nil)
