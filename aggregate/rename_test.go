package aggregate

import (
	"encoding/json"
	"testing"
)

func liveState() aggregateState {
	return aggregateState{Seq: 3, Exists: true, TenantID: testTenantID, Status: StatusActive}
}

// TestRename_HappyPath: a rename on a live investigation emits exactly one
// investigation.renamed event carrying the trimmed new title, with no paired
// interpretation (a rename is metadata, not a reasoning act).
func TestRename_HappyPath(t *testing.T) {
	env := newTestEnvelope("alice")
	events, err := applyCommand(env, RenameInvestigation{Title: "  RDP lateral movement — WIN-FILE01  "}, liveState())
	if err != nil {
		t.Fatalf("rename rejected: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("rename emitted %d events; want 1 (no paired interpretation)", len(events))
	}
	if events[0].Type != EventTypeRenamed {
		t.Fatalf("event type = %q; want %q", events[0].Type, EventTypeRenamed)
	}
	var p InvestigationRenamed
	if err := json.Unmarshal(events[0].Payload, &p); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if p.To != "RDP lateral movement — WIN-FILE01" {
		t.Errorf("title = %q; want the trimmed value", p.To)
	}
}

// TestRename_BlankRejected: whitespace-only titles are refused at the write path.
func TestRename_BlankRejected(t *testing.T) {
	env := newTestEnvelope("alice")
	if _, err := applyCommand(env, RenameInvestigation{Title: "   "}, liveState()); err == nil {
		t.Fatal("a blank title was accepted")
	}
}

// TestRename_ConcludedRejected: a settled record is not renamable (reopen first).
func TestRename_ConcludedRejected(t *testing.T) {
	env := newTestEnvelope("alice")
	concluded := liveState()
	concluded.Status = StatusConcluded
	if _, err := applyCommand(env, RenameInvestigation{Title: "new"}, concluded); err == nil {
		t.Fatal("renaming a concluded investigation was accepted")
	}
}

// TestRename_AIDenied: rename is human curation — an AI delegate cannot do it
// (it is deliberately off the aiAllowed allowlist, so it fails closed).
func TestRename_AIDenied(t *testing.T) {
	env := newTestEnvelope("agent")
	env.Actor.Kind = ActorAIDelegated
	if _, err := applyCommand(env, RenameInvestigation{Title: "AI pick"}, liveState()); err == nil {
		t.Fatal("an AI delegate was allowed to rename")
	}
}

// TestRename_NonexistentRejected: rename requires the aggregate to exist.
func TestRename_NonexistentRejected(t *testing.T) {
	env := newTestEnvelope("alice")
	if _, err := applyCommand(env, RenameInvestigation{Title: "x"}, aggregateState{TenantID: env.TenantID}); err == nil {
		t.Fatal("rename on a non-existent investigation was accepted")
	}
}
