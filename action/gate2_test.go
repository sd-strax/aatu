package action

import (
	"testing"
	"time"

	"github.com/sd-strax/reckon/aggregate"
)

func mustGate2(t *testing.T, policies ...Policy) *Gate2 {
	t.Helper()
	g, err := NewGate2(policies)
	if err != nil {
		t.Fatalf("NewGate2: %v", err)
	}
	return g
}

func baseInput() EvalInput {
	return EvalInput{
		ActionType:      "host.isolate",
		Tier:            aggregate.TierT2,
		Targets:         []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-A"}},
		RequestedByKind: "HUMAN",
		RequestedByID:   "alice",
		AllDirect:       true,
		Now:             time.Now(),
	}
}

// TestBaselineDenyBlocksAITier3 is the load-bearing invariant (04 §4.3 Example 2):
// an AI-delegated T3 request never auto-approves, even with an AUTO_APPROVE
// policy that matches — the baseline DENY wins.
func TestBaselineDenyBlocksAITier3(t *testing.T) {
	g := mustGate2(t, Policy{
		ID: "policy/auto-all/1.0.0", ActionMatch: []string{"*"},
		Effect: EffectAutoApprove, Predicate: "true",
	})
	in := baseInput()
	in.Tier = aggregate.TierT3
	in.RequestedByKind = "AI_DELEGATED"
	in.DelegateAgentID = "agent-7"

	d, err := g.Evaluate(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Mode != ModeManual || d.Effect != EffectDeny {
		t.Errorf("AI T3 → mode=%q effect=%q; want MANUAL/DENY (baseline)", d.Mode, d.Effect)
	}
	if d.MatchedPolicyRef != BaselineDenyPolicyID {
		t.Errorf("matched policy = %q; want the baseline", d.MatchedPolicyRef)
	}
}

// A HUMAN T3 with a matching AUTO_APPROVE policy DOES auto-approve — the baseline
// only fires for AI_DELEGATED.
func TestHumanTier3CanAutoApprove(t *testing.T) {
	g := mustGate2(t, Policy{
		ID: "policy/auto-all/1.0.0", ActionMatch: []string{"*"},
		Effect: EffectAutoApprove, Predicate: "true",
	})
	in := baseInput()
	in.Tier = aggregate.TierT3
	in.RequestedByKind = "HUMAN"

	d, _ := g.Evaluate(in)
	if !d.AutoApproves() {
		t.Errorf("human T3 with AUTO_APPROVE policy → mode %q; want AUTO_POLICY", d.Mode)
	}
}

// TestPriorityDenyOverTwoPartyOverAuto: when several policies match and fire,
// DENY > REQUIRE_TWO_PARTY > AUTO_APPROVE (04 §4.1).
func TestPriorityResolution(t *testing.T) {
	auto := Policy{ID: "p/auto/1", ActionMatch: []string{"*"}, Effect: EffectAutoApprove, Predicate: "true"}
	twoParty := Policy{ID: "p/2p/1", ActionMatch: []string{"*"}, Effect: EffectRequireTwoParty, Predicate: "true", SecondaryApproverPool: []string{"bob"}}
	deny := Policy{ID: "p/deny/1", ActionMatch: []string{"*"}, Effect: EffectDeny, Predicate: "ctx.evidence.all_direct == false"}

	// auto + two-party both fire → two-party wins.
	d, _ := mustGate2(t, auto, twoParty).Evaluate(baseInput())
	if d.Mode != ModeTwoParty || len(d.SecondaryApproverPool) != 1 {
		t.Errorf("auto+twoparty → mode=%q pool=%v; want TWO_PARTY with pool", d.Mode, d.SecondaryApproverPool)
	}

	// deny fires (evidence not all direct) alongside auto → deny wins → manual.
	in := baseInput()
	in.AllDirect = false
	d, _ = mustGate2(t, auto, deny).Evaluate(in)
	if d.Mode != ModeManual || d.Effect != EffectDeny {
		t.Errorf("auto+deny → mode=%q; want MANUAL/DENY", d.Mode)
	}
}

// TestShadowModeDoesNotDrive: a shadow AUTO_APPROVE is recorded as
// would_have_fired but the action still falls through to manual (04 §4.4).
func TestShadowModeDoesNotDrive(t *testing.T) {
	g := mustGate2(t, Policy{
		ID: "p/shadow-auto/1", ActionMatch: []string{"*"},
		Effect: EffectAutoApprove, Predicate: "true", Shadow: true,
	})
	d, _ := g.Evaluate(baseInput())
	if d.Mode != ModeManual {
		t.Errorf("shadow auto-approve drove the decision: mode=%q; want MANUAL", d.Mode)
	}
	// But it IS recorded as would_have_fired for the shadow audit.
	var found bool
	for _, e := range d.Evaluations {
		if e.PolicyRef == "p/shadow-auto/1" && e.WouldHaveFired && e.Shadow {
			found = true
		}
	}
	if !found {
		t.Error("shadow policy not recorded as would_have_fired in the audit")
	}
}

// TestFallThroughToManual: no matching policy → manual, empty matched ref.
func TestFallThroughToManual(t *testing.T) {
	g := mustGate2(t) // baseline only, which doesn't fire for a human T2
	d, _ := g.Evaluate(baseInput())
	if d.Mode != ModeManual || d.MatchedPolicyRef != "" || d.Effect != "" {
		t.Errorf("no match → %+v; want MANUAL with empty matched ref", d)
	}
}

// TestCELExamplePredicates exercises real predicate shapes from 04 §4.3:
// hypothesis existence with a strong sighting, and criticality any_in.
func TestCELExamplePredicates(t *testing.T) {
	// Example 1 shape: auto-isolate on a strong-evidence supported hypothesis.
	g := mustGate2(t, Policy{
		ID: "p/cobalt/1", ActionMatch: []string{"host.isolate"}, Effect: EffectAutoApprove,
		Predicate: `ctx.action.target_count == 1 &&
			ctx.evidence.hypotheses.exists(h, h.status == "SUPPORTED" &&
				h.supporting_sightings.exists(s, s.weight == "STRONG")) &&
			ctx.evidence.all_direct &&
			!ctx.targets.criticality_classes.any_in("prod-critical")`,
	})
	in := baseInput()
	in.Hypotheses = []map[string]any{{
		"status":               "SUPPORTED",
		"supporting_sightings": []map[string]any{{"weight": "STRONG"}},
	}}
	in.CriticalityClasses = []string{"workstation"}
	if d, _ := g.Evaluate(in); !d.AutoApproves() {
		t.Errorf("cobalt-strike example predicate did not auto-approve: %+v", d)
	}

	// Same predicate, but the target IS prod-critical → does not fire → manual.
	in.CriticalityClasses = []string{"prod-critical"}
	if d, _ := g.Evaluate(in); d.AutoApproves() {
		t.Error("predicate should not fire when target is prod-critical")
	}

	// Example 3 shape: require two-party for domain controllers.
	gdc := mustGate2(t, Policy{
		ID: "p/dc/1", ActionMatch: []string{"host.isolate"}, Effect: EffectRequireTwoParty,
		Predicate:             `ctx.targets.criticality_classes.any_in("domain-controller")`,
		SecondaryApproverPool: []string{"senior"},
	})
	in2 := baseInput()
	in2.CriticalityClasses = []string{"domain-controller"}
	if d, _ := gdc.Evaluate(in2); d.Mode != ModeTwoParty {
		t.Errorf("DC two-party predicate → mode %q; want TWO_PARTY", d.Mode)
	}
}

// TestBadPredicateRejectedAtBuild: a predicate that doesn't compile / isn't bool
// is a config error at NewGate2.
func TestBadPredicateRejectedAtBuild(t *testing.T) {
	if _, err := NewGate2([]Policy{{ID: "p/bad/1", ActionMatch: []string{"*"}, Predicate: "ctx.action.tier +"}}); err == nil {
		t.Error("malformed predicate accepted")
	}
	if _, err := NewGate2([]Policy{{ID: "p/nonbool/1", ActionMatch: []string{"*"}, Predicate: `ctx.action.type`}}); err == nil {
		t.Error("non-bool predicate accepted")
	}
}

// TestApplyDecisionAttachesAudit: the decision's evaluations become the command's
// PolicyEvaluations so the PolicyEvaluated event rides the request transaction.
func TestApplyDecisionAttachesAudit(t *testing.T) {
	g := mustGate2(t, Policy{ID: "p/auto/1", ActionMatch: []string{"*"}, Effect: EffectAutoApprove, Predicate: "true"})
	d, _ := g.Evaluate(baseInput())
	cmd := ApplyDecision(aggregate.RequestAction{ActionType: "host.isolate"}, d)
	if len(cmd.PolicyEvaluations) == 0 {
		t.Fatal("no evaluations attached to the command")
	}
	if cmd.MatchedPolicyRef != "p/auto/1" {
		t.Errorf("matched policy ref = %q; want p/auto/1", cmd.MatchedPolicyRef)
	}
}
