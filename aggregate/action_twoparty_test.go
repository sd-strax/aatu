package aggregate

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestApproveAction_TwoPartyRequiredRejectsSolo: an action whose frozen Gate 2
// requirement is TWO_PARTY can never be approved with a solo authorization — the
// aggregate boundary rejects it, so no approval surface can collapse two-person
// integrity into one (the Phase D two-party seam).
func TestApproveAction_TwoPartyRequiredRejectsSolo(t *testing.T) {
	env := newTestEnvelope("alice")
	id := uuid.New()
	state := aggregateState{
		Seq: 4, Exists: true, TenantID: env.TenantID, Status: StatusActive,
		Actions: map[uuid.UUID]actionState{
			id: {Status: ActionStatusRequested, Tier: TierT3, RequiredMode: AuthModeTwoParty},
		},
	}

	solo := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeManual, Stage: AuthStageSolo, PrimaryApproverRef: "alice", PrimaryApprovedAt: time.Now(),
	}}
	if _, err := applyCommand(env, solo, state); err == nil {
		t.Fatal("a solo MANUAL approval on a TWO_PARTY-required action was accepted")
	}

	// The proper primary approval (mode TWO_PARTY, stage PRIMARY) is accepted.
	primary := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeTwoParty, Stage: AuthStagePrimary, PrimaryApproverRef: "alice", PrimaryApprovedAt: time.Now(),
	}}
	if _, err := applyCommand(env, primary, state); err != nil {
		t.Fatalf("proper primary approval rejected: %v", err)
	}
}

// TestApproveAction_SecondaryApproverPool: when the policy declared a secondary
// approver pool, the secondary must be drawn from it — an out-of-pool approver
// is rejected even though they are distinct from the primary.
func TestApproveAction_SecondaryApproverPool(t *testing.T) {
	id := uuid.New()
	secTime := time.Now()
	pend := func() aggregateState {
		return aggregateState{
			Seq: 6, Exists: true, TenantID: testTenantID, Status: StatusActive,
			Actions: map[uuid.UUID]actionState{
				id: {
					Status: ActionStatusPendingSecondary, Tier: TierT3,
					RequiredMode: AuthModeTwoParty, PrimaryApprover: "alice",
					SecondaryApproverPool: []string{"bob"},
				},
			},
		}
	}

	// carol is distinct from alice but not in the pool → rejected.
	carol := newTestEnvelope("carol")
	carolSec := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeTwoParty, Stage: AuthStageSecondary,
		PrimaryApproverRef: "alice", SecondaryApproverRef: "carol", SecondaryApprovedAt: &secTime,
	}}
	if _, err := applyCommand(carol, carolSec, pend()); err == nil {
		t.Error("out-of-pool secondary approver was accepted")
	}

	// bob is in the pool → accepted.
	bob := newTestEnvelope("bob")
	bobSec := ApproveAction{ActionID: id, Authorization: Authorization{
		Mode: AuthModeTwoParty, Stage: AuthStageSecondary,
		PrimaryApproverRef: "alice", SecondaryApproverRef: "bob", SecondaryApprovedAt: &secTime,
	}}
	events, err := applyCommand(bob, bobSec, pend())
	if err != nil {
		t.Fatalf("in-pool secondary approver rejected: %v", err)
	}
	if foldInto(pend().Actions, events)[id].Status != ActionStatusApproved {
		t.Error("after in-pool secondary, status should be APPROVED")
	}
}
