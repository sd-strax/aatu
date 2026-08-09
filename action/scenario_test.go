package action

import (
	"context"
	"testing"
	"time"

	"github.com/sd-strax/reckon/aggregate"
)

// TestShippedActionScenario loads the committed write-side config + bundled
// action fixtures and drives request → resolve → dispatch end to end — a
// regression guard that the shipped fixtures/config stay valid and wired.
func TestShippedActionScenario(t *testing.T) {
	cfg, err := LoadActionConfig("../examples/action/lateral-movement.yaml")
	if err != nil {
		t.Fatalf("load shipped action config: %v", err)
	}
	resolver, catalog, err := BuildActionResolver(cfg, "../fixtures")
	if err != nil {
		t.Fatalf("build resolver: %v", err)
	}

	// host.isolate, account.disable/enable, ioc.block/unblock, and the ticketing
	// family advertise as available.
	avail := map[string]ActionAvailability{}
	for _, s := range resolver.ListActionTypes(catalog) {
		avail[s.Descriptor.ActionType] = s.Status
	}
	for _, at := range []string{
		"host.isolate", "account.disable", "account.enable", "ioc.block", "ioc.unblock",
		"ticket.create", "ticket.comment", "ticket.transition", "ticket.close",
	} {
		if avail[at] != ActionAvailable {
			t.Errorf("bound action %s = %q; want available", at, avail[at])
		}
	}

	// ioc.block dispatches end-to-end against the C2 indicator — the containment
	// the agent could not complete before the catalog was frozen + surfaced.
	blockCmd, err := BuildRequestCommand(catalog, ActionRequest{
		ActionType:   "ioc.block",
		Targets:      []aggregate.TargetSpec{{EntityRef: "ipv4-addr--1", ResolvedIdentifier: "185.220.101.5"}},
		EvidenceRefs: []string{"observed-data--c2"},
		Rationale:    "block the C2 channel",
	}, time.Now())
	if err != nil {
		t.Fatalf("build ioc.block request: %v", err)
	}
	blockRes, _, err := resolver.Resolve(context.Background(), DispatchRequest{
		ActionID:   blockCmd.ActionID,
		ActionType: blockCmd.ActionType,
		Targets:    blockCmd.Targets,
	})
	if err != nil {
		t.Fatalf("resolve/dispatch ioc.block: %v", err)
	}
	if blockRes.FinalOutcome != OutcomeSucceeded {
		t.Errorf("ioc.block outcome = %q; want SUCCEEDED", blockRes.FinalOutcome)
	}

	// ioc.unblock dispatches as a standalone action — not a tracked reversal of
	// the block (04 §7): no reversal_of_ref, and the block record stays SUCCEEDED.
	unblockCmd, err := BuildRequestCommand(catalog, ActionRequest{
		ActionType:   "ioc.unblock",
		Targets:      []aggregate.TargetSpec{{EntityRef: "ipv4-addr--1", ResolvedIdentifier: "185.220.101.5"}},
		EvidenceRefs: []string{"observed-data--c2"},
		Rationale:    "shared CDN edge — legit traffic breaking; analyst judged removal safe",
	}, time.Now())
	if err != nil {
		t.Fatalf("build ioc.unblock request: %v", err)
	}
	unblockRes, _, err := resolver.Resolve(context.Background(), DispatchRequest{
		ActionID:   unblockCmd.ActionID,
		ActionType: unblockCmd.ActionType,
		Targets:    unblockCmd.Targets,
	})
	if err != nil {
		t.Fatalf("resolve/dispatch ioc.unblock: %v", err)
	}
	if unblockRes.FinalOutcome != OutcomeSucceeded {
		t.Errorf("ioc.unblock outcome = %q; want SUCCEEDED", unblockRes.FinalOutcome)
	}

	// ticket.create dispatches end-to-end — the operational handoff (04 §2.2):
	// target = the DESTINATION queue (not the hosts being handed off, which ride
	// in evidence_refs); irreversible-additive, stays T2.
	ticketCmd, err := BuildRequestCommand(catalog, ActionRequest{
		ActionType:   "ticket.create",
		Targets:      []aggregate.TargetSpec{{ResolvedIdentifier: "IT-OPS"}},
		EvidenceRefs: []string{"x-host--1"},
		Parameters:   []byte(`{"summary":"Reimage WIN-FILE01 after RDP lateral movement","issue_type":"remediation"}`),
		Rationale:    "hand off host rebuild to IT after containment",
	}, time.Now())
	if err != nil {
		t.Fatalf("build ticket.create request: %v", err)
	}
	if ticketCmd.Tier != aggregate.TierT2 || ticketCmd.Reversibility != ReversibilityIrreversible {
		t.Errorf("ticket.create tier/reversibility = %s/%s; want T2/irreversible", ticketCmd.Tier, ticketCmd.Reversibility)
	}
	ticketRes, _, err := resolver.Resolve(context.Background(), DispatchRequest{
		ActionID:   ticketCmd.ActionID,
		ActionType: ticketCmd.ActionType,
		Targets:    ticketCmd.Targets,
	})
	if err != nil {
		t.Fatalf("resolve/dispatch ticket.create: %v", err)
	}
	if ticketRes.FinalOutcome != OutcomeSucceeded {
		t.Errorf("ticket.create outcome = %q; want SUCCEEDED", ticketRes.FinalOutcome)
	}

	// Build a request_action for host.isolate (T2, single target), then dispatch
	// it through the resolver into the fixture write adapter.
	cmd, err := BuildRequestCommand(catalog, ActionRequest{
		ActionType:   "host.isolate",
		Targets:      []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-FILE01"}},
		EvidenceRefs: []string{"observed-data--rdp"},
		Rationale:    "contain the RDP lateral movement",
	}, time.Now())
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if cmd.Tier != aggregate.TierT2 {
		t.Errorf("host.isolate tier = %q; want T2", cmd.Tier)
	}

	res, binding, err := resolver.Resolve(context.Background(), DispatchRequest{
		ActionID:   cmd.ActionID,
		ActionType: cmd.ActionType,
		Targets:    cmd.Targets,
	})
	if err != nil {
		t.Fatalf("resolve/dispatch: %v", err)
	}
	if res.FinalOutcome != OutcomeSucceeded {
		t.Errorf("dispatch outcome = %q; want SUCCEEDED", res.FinalOutcome)
	}
	if binding.Adapter != "fixture_write" || res.AuditDepth != AuditFull {
		t.Errorf("unexpected binding/audit: %s / %s", binding.Adapter, res.AuditDepth)
	}
	if res.AdapterRequestID == "" {
		t.Error("no adapter_request_id stamped")
	}
}
