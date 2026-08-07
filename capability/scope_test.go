package capability

import (
	"context"
	"fmt"
	"testing"
)

// TestScopeApplicable is the §3.5 fail-closed truth table shared by both
// resolvers.
func TestScopeApplicable(t *testing.T) {
	cases := []struct {
		instance, investigation string
		want                    bool
	}{
		{"", "", true},              // unscoped instance, single-organization tenant
		{"", "acme", true},          // unscoped instance (shared tool) serves any scope
		{"acme", "acme", true},      // exact match
		{"acme", "meridian", false}, // wrong organization
		{"acme", "", false},         // scoped instance never serves an unscoped investigation
	}
	for _, c := range cases {
		if got := ScopeApplicable(c.instance, c.investigation); got != c.want {
			t.Errorf("ScopeApplicable(%q, %q) = %v; want %v", c.instance, c.investigation, got, c.want)
		}
	}
}

func scopedBinding(adapter, scope string) Binding {
	return Binding{Adapter: adapter, Operation: "op", Priority: 100, Scope: scope}
}

// TestResolveRoutesByScope: two scoped instances of one verb — a call reaches
// only the instance whose scope matches the investigation.
func TestResolveRoutesByScope(t *testing.T) {
	acme := healthyStub("acme")
	meridian := healthyStub("meridian")
	res := newResolver(
		map[string][]Binding{"get_entity_context": {
			scopedBinding("acme", "acme"),
			scopedBinding("meridian", "meridian"),
		}},
		map[string]Adapter{"acme": acme, "meridian": meridian},
	)

	out, err := res.Resolve(context.Background(), "get_entity_context", CallInput{SourceScope: "acme"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if out.Coverage != CoverageComplete {
		t.Errorf("coverage = %s; want COMPLETE", out.Coverage)
	}
	if acme.calls != 1 || meridian.calls != 0 {
		t.Errorf("routing: acme=%d meridian=%d; want acme once, meridian never", acme.calls, meridian.calls)
	}
}

// TestResolveScopeMismatchIsUnavailable: an investigation whose scope matches no
// scoped instance (and no unscoped instance exists) degrades to
// UNAVAILABLE_TENANT with nothing invoked — the fail-closed guarantee.
func TestResolveScopeMismatchIsUnavailable(t *testing.T) {
	acme := healthyStub("acme")
	res := newResolver(
		map[string][]Binding{"v": {scopedBinding("acme", "acme")}},
		map[string]Adapter{"acme": acme},
	)
	for _, scope := range []string{"meridian", ""} {
		out, _ := res.Resolve(context.Background(), "v", CallInput{SourceScope: scope})
		if out.Coverage != CoverageUnavailableTenant {
			t.Errorf("scope %q: coverage = %s; want UNAVAILABLE_TENANT", scope, out.Coverage)
		}
	}
	if acme.calls != 0 {
		t.Errorf("scoped instance invoked for a mismatched scope: calls=%d", acme.calls)
	}
}

// TestResolveUnscopedInstanceServesAnyScope: an unscoped instance (a shared tool
// like threat intel) answers for every investigation scope.
func TestResolveUnscopedInstanceServesAnyScope(t *testing.T) {
	ti := healthyStub("ti")
	res := newResolver(
		map[string][]Binding{"v": {scopedBinding("ti", "")}},
		map[string]Adapter{"ti": ti},
	)
	for _, scope := range []string{"acme", "meridian", ""} {
		out, _ := res.Resolve(context.Background(), "v", CallInput{SourceScope: scope})
		if out.Coverage != CoverageComplete {
			t.Errorf("scope %q: coverage = %s; want COMPLETE", scope, out.Coverage)
		}
	}
	if ti.calls != 3 {
		t.Errorf("unscoped instance calls = %d; want 3 (served every scope)", ti.calls)
	}
}

// TestResolveScopedIdentityDistinct: identity is minted in the scope's namespace
// (§3.5). The same entity resolves to different STIX ids under different scopes,
// the same id under the same scope, and neither equals the unscoped id.
func TestResolveScopedIdentityDistinct(t *testing.T) {
	refs := func(scope string) string {
		res := newResolver(
			map[string][]Binding{"v": {scopedBinding("shared", "")}},
			map[string]Adapter{"shared": healthyStub("shared")},
		)
		out, err := res.Resolve(context.Background(), "v", CallInput{SourceScope: scope})
		if err != nil {
			t.Fatalf("resolve %q: %v", scope, err)
		}
		if len(out.EntityRefs) == 0 {
			t.Fatalf("scope %q: no entity refs produced", scope)
		}
		return fmt.Sprint(out.EntityRefs)
	}

	acme, meridian, acmeAgain, unscoped := refs("acme"), refs("meridian"), refs("acme"), refs("")
	if acme == meridian {
		t.Errorf("same ids across scopes (cross-organization merge): %s", acme)
	}
	if acme != acmeAgain {
		t.Errorf("unstable ids within a scope: %s vs %s", acme, acmeAgain)
	}
	if acme == unscoped {
		t.Errorf("scoped ids equal unscoped ids: %s", acme)
	}
}
