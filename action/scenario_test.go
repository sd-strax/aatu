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

	// host.isolate, account.disable/enable, and ioc.block advertise as available.
	avail := map[string]ActionAvailability{}
	for _, s := range resolver.ListActionTypes(catalog) {
		avail[s.Descriptor.ActionType] = s.Status
	}
	if avail["host.isolate"] != ActionAvailable || avail["account.disable"] != ActionAvailable ||
		avail["account.enable"] != ActionAvailable || avail["ioc.block"] != ActionAvailable ||
		avail["ioc.unblock"] != ActionAvailable {
		t.Errorf("bound actions not available: %v", avail)
	}

	// ioc.block dispatches end-to-end against the C2 indicator — the containment
	// the agent could not complete before the catalog was frozen + surfaced.
	blockCmd, err := BuildRequestCommand(catalog, ActionRequest{
		ActionType: "ioc.block",
		Targets:    []aggregate.TargetSpec{{EntityRef: "ipv4-addr--1", ResolvedIdentifier: "185.220.101.5"}},
		Rationale:  "block the C2 channel",
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
		ActionType: "ioc.unblock",
		Targets:    []aggregate.TargetSpec{{EntityRef: "ipv4-addr--1", ResolvedIdentifier: "185.220.101.5"}},
		Rationale:  "shared CDN edge — legit traffic breaking; analyst judged removal safe",
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

	// Build a request_action for host.isolate (T2, single target), then dispatch
	// it through the resolver into the fixture write adapter.
	cmd, err := BuildRequestCommand(catalog, ActionRequest{
		ActionType: "host.isolate",
		Targets:    []aggregate.TargetSpec{{EntityRef: "x-host--1", ResolvedIdentifier: "WIN-FILE01"}},
		Rationale:  "contain the RDP lateral movement",
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
