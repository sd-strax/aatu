package aggregate

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// verdictState builds a live, pinned investigation state (the pin gate is
// satisfied) optionally carrying a prior verdict of record.
func verdictState(prior ...verdictEntry) aggregateState {
	pinID := uuid.New()
	return aggregateState{
		Seq: 5, Exists: true, TenantID: testTenantID, Status: StatusActive,
		Pins:              map[uuid.UUID]bool{pinID: true},
		Verdicts:          prior,
		Interpretations:   map[uuid.UUID]string{pinID: InterpretationEvidencePin},
		SupersededInterps: map[uuid.UUID]bool{},
	}
}

func recordVerdictCmd(disposition string) (RecordInterpretation, uuid.UUID) {
	id := uuid.New()
	return RecordInterpretation{
		InterpretationID:   id,
		InterpretationType: InterpretationVerdict,
		Verdict:            &VerdictNode{Disposition: disposition},
		InputRefs:          []string{"observed-data--x"},
		Rationale:          "cited by the pinned finding",
	}, id
}

// TestVerdict_ReRecordAutoSupersedes: recording a second verdict emits, in one
// transaction, a supersession of the prior verdict of record (pointing at the
// new one) followed by the new verdict act — so the thread reads as a revision,
// not two co-equal verdicts.
func TestVerdict_ReRecordAutoSupersedes(t *testing.T) {
	env := newTestEnvelope("alice")
	priorID := uuid.New()
	state := verdictState(verdictEntry{InterpID: priorID, Disposition: VerdictBenign})

	cmd, newID := recordVerdictCmd(VerdictMalicious)
	events, err := applyCommand(env, cmd, state)
	if err != nil {
		t.Fatalf("re-record verdict rejected: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d events; want 2 (supersede prior + record new)", len(events))
	}
	if events[0].Type != EventTypeInterpretationSuperseded {
		t.Fatalf("event[0] = %q; want %q", events[0].Type, EventTypeInterpretationSuperseded)
	}
	var sup InterpretationSupersededPayload
	if err := json.Unmarshal(events[0].Payload, &sup); err != nil {
		t.Fatalf("unmarshal supersede payload: %v", err)
	}
	if sup.SupersededID != priorID {
		t.Errorf("superseded id = %s; want prior %s", sup.SupersededID, priorID)
	}
	if sup.SupersedingID != newID {
		t.Errorf("superseding id = %s; want new %s", sup.SupersedingID, newID)
	}
	if sup.SupersededType != InterpretationVerdict {
		t.Errorf("superseded type = %q; want verdict", sup.SupersededType)
	}
	if events[1].Type != EventTypeInterpretationRecorded {
		t.Fatalf("event[1] = %q; want recorded", events[1].Type)
	}
	if events[0].SequenceNo != 6 || events[1].SequenceNo != 7 {
		t.Errorf("sequence = %d,%d; want 6,7 (contiguous after seq 5)", events[0].SequenceNo, events[1].SequenceNo)
	}
}

// TestVerdict_FirstRecordNoSupersede: the first verdict has nothing to
// supersede, so it emits exactly one event.
func TestVerdict_FirstRecordNoSupersede(t *testing.T) {
	env := newTestEnvelope("alice")
	cmd, _ := recordVerdictCmd(VerdictMalicious)
	events, err := applyCommand(env, cmd, verdictState())
	if err != nil {
		t.Fatalf("first verdict rejected: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events; want 1 (no prior verdict to supersede)", len(events))
	}
	if events[0].Type != EventTypeInterpretationRecorded {
		t.Errorf("event type = %q; want recorded", events[0].Type)
	}
}

// TestVerdict_ReRecordFoldsToNewDisposition: after the auto-supersede pair is
// folded back, the disposition of record is the revised one and only it remains
// non-superseded.
func TestVerdict_ReRecordFoldsToNewDisposition(t *testing.T) {
	env := newTestEnvelope("alice")
	priorID := uuid.New()
	state := verdictState(verdictEntry{InterpID: priorID, Disposition: VerdictBenign})

	cmd, newID := recordVerdictCmd(VerdictMalicious)
	events, err := applyCommand(env, cmd, state)
	if err != nil {
		t.Fatalf("re-record verdict rejected: %v", err)
	}
	// Fold the emitted events onto the pre-command state's verdict list.
	folded := state
	for _, e := range events {
		switch e.Type {
		case EventTypeInterpretationSuperseded:
			var p InterpretationSupersededPayload
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				t.Fatal(err)
			}
			foldSupersession(&folded, p)
		case EventTypeInterpretationRecorded:
			folded.Verdicts = append(folded.Verdicts, verdictEntry{InterpID: newID, Disposition: VerdictMalicious})
		}
	}
	if got := folded.CurrentVerdict(); got != VerdictMalicious {
		t.Errorf("disposition of record = %q; want %q", got, VerdictMalicious)
	}
	live := 0
	for _, v := range folded.Verdicts {
		if !v.Superseded {
			live++
		}
	}
	if live != 1 {
		t.Errorf("live (non-superseded) verdicts = %d; want exactly 1", live)
	}
}
