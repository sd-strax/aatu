package action

import "sync/atomic"

// AtomicResolver is a concurrency-safe swappable holder for the write-side
// action resolver. It exists for the no-restart reload (11 §5.1): the Temporal
// dispatch activities hold one of these instead of a bare *ActionResolver, so a
// tenant-config edit can swap in a freshly-built resolver while in-flight
// dispatches keep the resolver they already Loaded (a resolver is immutable
// once built, so this is safe without draining). The read side achieves the
// same with the backend's capabilitySurface pointer swap; this is its write-
// side twin, needed because the resolver lives in the durable worker.
type AtomicResolver struct {
	p atomic.Pointer[ActionResolver]
}

// NewAtomicResolver wraps an initial resolver (may be nil — a worker registered
// before any write binding exists holds an empty one).
func NewAtomicResolver(r *ActionResolver) *AtomicResolver {
	a := &AtomicResolver{}
	a.p.Store(r)
	return a
}

// Load returns the current resolver.
func (a *AtomicResolver) Load() *ActionResolver { return a.p.Load() }

// Store swaps in a rebuilt resolver — the reload's write-side apply.
func (a *AtomicResolver) Store(r *ActionResolver) { a.p.Store(r) }
