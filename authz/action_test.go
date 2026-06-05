package authz

import (
	"context"
	"testing"
)

func TestPermissiveGate2_AlwaysAutoApproves(t *testing.T) {
	var g Gate2 = PermissiveGate2{}
	cases := []ActionRequest{
		{ActionType: "host.isolate", Targets: 1, Reversibility: "REVERSIBLE"},
		{ActionType: "ioc.publish", Targets: 100, Reversibility: "IRREVERSIBLE"},
		{ActionType: "account.disable", Targets: 50, Reversibility: "BEST_EFFORT"},
		{}, // zero-value
	}
	for _, c := range cases {
		got, err := g.Evaluate(context.Background(), Claims{Subject: "x"}, c)
		if err != nil {
			t.Errorf("Evaluate(%+v) returned error: %v", c, err)
		}
		if got != DecisionAutoApprove {
			t.Errorf("Evaluate(%+v) = %v; want DecisionAutoApprove", c, got)
		}
	}
}

func TestGate2_InterfaceContract(t *testing.T) {
	// Compile-time check: PermissiveGate2 satisfies the Gate2 interface.
	// Useful so that swapping in the Phase C implementation can be detected
	// by a compile-time test failure if the interface drifts.
	var _ Gate2 = PermissiveGate2{}
}
