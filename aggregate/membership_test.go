package aggregate

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// eventsOfType returns the payloads of an aggregate's events of a given type,
// in sequence order.
func eventsOfType(t *testing.T, aggID uuid.UUID, eventType string) []json.RawMessage {
	t.Helper()
	stream, err := NewStore(testDB).LoadStream(context.Background(), aggID)
	if err != nil {
		t.Fatalf("LoadStream: %v", err)
	}
	var out []json.RawMessage
	for _, e := range stream {
		if e.Type == eventType {
			out = append(out, e.Payload)
		}
	}
	return out
}

// TestMembership_AddRemoveAttach drives the three membership commands and
// confirms each writes a single (unpaired) event with the expected payload.
func TestMembership_AddRemoveAttach(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	h := newTestHandler()
	aggID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), CreateInvestigation{Title: "INV-M"})
	mustHandle(t, h, cmdEnv(aggID), ActivateInvestigation{})

	// AddMember writes exactly one event (no paired interpretation).
	addRes := mustHandle(t, h, cmdEnv(aggID), AddMember{StixObjectRef: "ipv4-addr--1", Rationale: "C2 beacon dest"})
	if len(addRes.AppliedEvents) != 1 {
		t.Fatalf("AddMember produced %d events; want 1 (membership is unpaired)", len(addRes.AppliedEvents))
	}

	mustHandle(t, h, cmdEnv(aggID), RemoveMember{StixObjectRef: "ipv4-addr--1", Reason: "benign on review"})

	interpID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), AttachEvidence{
		EvidenceRef:       "ocsf-event--42",
		InterpretationRef: interpID,
		Role:              RoleSupports,
		Weight:            WeightStrong,
	})

	if got := eventsOfType(t, aggID, EventTypeMemberAdded); len(got) != 1 {
		t.Errorf("member_added count = %d; want 1", len(got))
	}
	if got := eventsOfType(t, aggID, EventTypeMemberRemoved); len(got) != 1 {
		t.Errorf("member_removed count = %d; want 1", len(got))
	}
	ev := eventsOfType(t, aggID, EventTypeEvidenceAttached)
	if len(ev) != 1 {
		t.Fatalf("evidence_attached count = %d; want 1", len(ev))
	}
	var ea EvidenceAttached
	if err := json.Unmarshal(ev[0], &ea); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if ea.InterpretationRef != interpID || ea.Role != RoleSupports || ea.Weight != WeightStrong {
		t.Errorf("evidence payload = %+v; unexpected", ea)
	}

	// No InterpretationRecorded should have been emitted by membership commands
	// (the only interpretations here come from the lifecycle activate).
	if got := eventsOfType(t, aggID, EventTypeInterpretationRecorded); len(got) != 1 {
		t.Errorf("interpretation count = %d; want 1 (from activate only)", len(got))
	}
}

// TestMembership_Validation rejects malformed membership commands.
func TestMembership_Validation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	h := newTestHandler()
	ctx := context.Background()
	aggID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), CreateInvestigation{Title: "INV-MV"})

	cases := []Command{
		AddMember{},                                          // empty ref
		RemoveMember{},                                       // empty ref
		AttachEvidence{InterpretationRef: uuid.New(), Role: RoleSupports, Weight: WeightStrong}, // empty evidence ref
		AttachEvidence{EvidenceRef: "e", Role: RoleSupports, Weight: WeightStrong},              // zero interpretation ref
		AttachEvidence{EvidenceRef: "e", InterpretationRef: uuid.New(), Role: "maybe", Weight: WeightStrong}, // bad role
		AttachEvidence{EvidenceRef: "e", InterpretationRef: uuid.New(), Role: RoleSupports, Weight: "HUGE"},  // bad weight
	}
	for _, c := range cases {
		if _, err := h.Handle(ctx, cmdEnv(aggID), c); err == nil {
			t.Errorf("%s with invalid payload should fail validation", c.Kind())
		}
	}
}

// TestMembership_RejectedWhenConcluded confirms scope edits need an open
// investigation — concluded requires a reopen first, archived is terminal.
func TestMembership_RejectedWhenConcluded(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	h := newTestHandler()
	ctx := context.Background()
	aggID := uuid.New()
	mustHandle(t, h, cmdEnv(aggID), CreateInvestigation{Title: "INV-MC"})
	mustHandle(t, h, cmdEnv(aggID), ActivateInvestigation{})
	mustHandle(t, h, cmdEnv(aggID), ConcludeInvestigation{ReportRef: "report--c"})

	if _, err := h.Handle(ctx, cmdEnv(aggID), AddMember{StixObjectRef: "url--1"}); err == nil {
		t.Error("AddMember on concluded investigation should fail")
	}

	// After reopen it is allowed again.
	mustHandle(t, h, cmdEnv(aggID), ReopenInvestigation{})
	if _, err := h.Handle(ctx, cmdEnv(aggID), AddMember{StixObjectRef: "url--1"}); err != nil {
		t.Errorf("AddMember after reopen should succeed: %v", err)
	}
}
