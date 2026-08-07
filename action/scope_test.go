package action

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
)

func scopedActionBinding(adapter, scope string) ActionBinding {
	return ActionBinding{Adapter: adapter, Operation: "op", Priority: 100, Scope: scope}
}

// TestActionResolveRoutesByScope: the write resolver dispatches to the instance
// whose scope matches the investigation and never the other organization's.
func TestActionResolveRoutesByScope(t *testing.T) {
	acme := &stubWriteAdapter{name: "acme", healthy: true, result: okResult()}
	meridian := &stubWriteAdapter{name: "meridian", healthy: true, result: okResult()}
	r := NewActionResolver(
		map[string][]ActionBinding{"account.disable": {
			scopedActionBinding("acme", "acme"),
			scopedActionBinding("meridian", "meridian"),
		}},
		map[string]WriteAdapter{"acme": acme, "meridian": meridian},
	)

	req := DispatchRequest{
		ActionID:    uuid.New(),
		ActionType:  "account.disable",
		Targets:     []aggregate.TargetSpec{target("jdoe")},
		SourceScope: "meridian",
	}
	_, binding, err := r.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if binding.Adapter != "meridian" {
		t.Errorf("dispatched to %q; want meridian", binding.Adapter)
	}
	if meridian.calls != 1 || acme.calls != 0 {
		t.Errorf("routing: meridian=%d acme=%d; want meridian once, acme never", meridian.calls, acme.calls)
	}
}

// TestActionResolveScopeMismatchNoDispatch: with no matching-scope instance the
// no-fall-through write resolver reports ErrNoBinding and dispatches nothing —
// the mis-routed-write failure mode (§3.5) can never occur.
func TestActionResolveScopeMismatchNoDispatch(t *testing.T) {
	acme := &stubWriteAdapter{name: "acme", healthy: true, result: okResult()}
	r := NewActionResolver(
		map[string][]ActionBinding{"account.disable": {scopedActionBinding("acme", "acme")}},
		map[string]WriteAdapter{"acme": acme},
	)
	for _, scope := range []string{"meridian", ""} {
		req := DispatchRequest{
			ActionID:    uuid.New(),
			ActionType:  "account.disable",
			Targets:     []aggregate.TargetSpec{target("jdoe")},
			SourceScope: scope,
		}
		if _, _, err := r.Resolve(context.Background(), req); !errors.Is(err, ErrNoBinding) {
			t.Errorf("scope %q: err = %v; want ErrNoBinding", scope, err)
		}
	}
	if acme.calls != 0 {
		t.Errorf("a mismatched-scope dispatch happened: calls=%d", acme.calls)
	}
}
