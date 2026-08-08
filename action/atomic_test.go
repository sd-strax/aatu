package action

import "testing"

// TestAtomicResolverSwap: Load returns the current resolver; Store swaps it —
// the write-side reload primitive (11 §5.1).
func TestAtomicResolverSwap(t *testing.T) {
	first := NewActionResolver(map[string][]ActionBinding{
		"host.isolate": {{ActionType: "host.isolate", Adapter: "a", Operation: "op", Priority: 1}},
	}, nil)
	holder := NewAtomicResolver(first)
	if holder.Load() != first {
		t.Fatal("Load did not return the initial resolver")
	}

	second := NewActionResolver(map[string][]ActionBinding{
		"host.isolate":    {{ActionType: "host.isolate", Adapter: "b", Operation: "op", Priority: 1}},
		"account.disable": {{ActionType: "account.disable", Adapter: "b", Operation: "op", Priority: 1}},
	}, nil)
	holder.Store(second)
	if holder.Load() != second {
		t.Error("Store did not swap the resolver")
	}
}

// TestAtomicResolverNilInitial: a holder may start nil (a worker registered
// before any write binding existed); Store then installs the real one.
func TestAtomicResolverNilInitial(t *testing.T) {
	holder := NewAtomicResolver(nil)
	if holder.Load() != nil {
		t.Fatal("nil-initialized holder should Load nil")
	}
	r := NewActionResolver(nil, nil)
	holder.Store(r)
	if holder.Load() != r {
		t.Error("Store into a nil-initialized holder failed")
	}
}
