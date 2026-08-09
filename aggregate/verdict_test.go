package aggregate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func mustUnmarshal(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func decodeInterp(t *testing.T, e Event) InterpretationRecorded {
	t.Helper()
	if e.Type != EventTypeInterpretationRecorded {
		t.Fatalf("event type = %q; want %q", e.Type, EventTypeInterpretationRecorded)
	}
	var rec InterpretationRecorded
	mustUnmarshal(t, e.Payload, &rec)
	return rec
}

// activeState is a folded ACTIVE investigation for pure applyCommand tests.
func activeState(env Envelope) aggregateState {
	return aggregateState{
		Seq: 3, Exists: true, TenantID: env.TenantID, Status: StatusActive,
		Actions:           map[uuid.UUID]actionState{},
		Hypotheses:        map[string]hypothesisState{},
		Predictions:       map[string]predictionState{},
		Interpretations:   map[uuid.UUID]string{},
		SupersededInterps: map[uuid.UUID]bool{},
		Pins:              map[uuid.UUID]bool{},
	}
}

func pinCmd() RecordInterpretation {
	return RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationEvidencePin,
		InputRefs:          []string{"observed-data--od1"},
		Rationale:          "first-seen ASN for this user",
	}
}

func verdictCmd() RecordInterpretation {
	return RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationVerdict,
		Verdict:            &VerdictNode{Disposition: VerdictMalicious},
		InputRefs:          []string{"observed-data--od1"},
		Rationale:          "lateral movement confirmed by the pinned logons",
	}
}

// TestEvidencePin_RequiresCitation: a pin with nothing cited is rejected at
// Validate — curation must point at evidence.
func TestEvidencePin_RequiresCitation(t *testing.T) {
	env := newTestEnvelope("alice")
	cmd := pinCmd()
	cmd.InputRefs = nil
	if _, err := applyCommand(env, cmd, activeState(env)); err == nil {
		t.Fatal("evidence-pin without input_refs accepted")
	}
}

// TestVerdict_RequiresPin: the single most important gate — no verdict on an
// investigation with zero pinned evidence.
func TestVerdict_RequiresPin(t *testing.T) {
	env := newTestEnvelope("alice")
	if _, err := applyCommand(env, verdictCmd(), activeState(env)); err == nil ||
		!strings.Contains(err.Error(), "pinned evidence") {
		t.Fatalf("verdict without a pin: err = %v; want the pinned-evidence rejection", err)
	}
}

// TestVerdict_ShapeGuards: disposition enum, evidence citation, and
// no-smuggling (a verdict payload on another type) are all Validate-level.
func TestVerdict_ShapeGuards(t *testing.T) {
	env := newTestEnvelope("alice")
	st := activeState(env)

	bad := verdictCmd()
	bad.Verdict.Disposition = "GUILTY"
	if _, err := applyCommand(env, bad, st); err == nil {
		t.Error("invalid disposition accepted")
	}

	noEvidence := verdictCmd()
	noEvidence.InputRefs = nil
	if _, err := applyCommand(env, noEvidence, st); err == nil {
		t.Error("verdict without cited evidence accepted")
	}

	smuggled := pinCmd()
	smuggled.Verdict = &VerdictNode{Disposition: VerdictBenign}
	if _, err := applyCommand(env, smuggled, st); err == nil {
		t.Error("verdict payload on a non-verdict type accepted")
	}

	stampSmuggle := RecordInterpretation{
		InterpretationID: uuid.New(), InterpretationType: InterpretationPivot,
		Rationale: "r", AIVerdictConfigRef: "trust.ai_verdict",
	}
	if _, err := applyCommand(env, stampSmuggle, st); err == nil {
		t.Error("ai_verdict_config_ref on a non-verdict type accepted")
	}
}

// TestVerdict_AIDialDefaultDeny: an AI-delegated verdict without the tenant
// dial's stamp is denied; with the stamp it records, and the enabling config
// ref rides the event payload (the audit shows what authorized the delegate).
func TestVerdict_AIDialDefaultDeny(t *testing.T) {
	env := newTestEnvelope("alice")
	env.Actor.Kind = ActorAIDelegated
	env.Actor.Delegate = &AIDelegate{Vendor: "claude", Model: "m"}
	st := activeState(env)
	st.Pins[uuid.New()] = true

	if _, err := applyCommand(env, verdictCmd(), st); err == nil ||
		!strings.Contains(err.Error(), "denied by default") {
		t.Fatalf("AI verdict without stamp: err = %v; want the default-deny rejection", err)
	}

	stamped := verdictCmd()
	stamped.AIVerdictConfigRef = "trust.ai_verdict"
	events, err := applyCommand(env, stamped, st)
	if err != nil {
		t.Fatalf("AI verdict with stamp: %v", err)
	}
	rec := decodeInterp(t, events[0])
	if rec.Verdict == nil || rec.Verdict.ConfigRef != "trust.ai_verdict" {
		t.Errorf("event verdict = %+v; want the enabling config ref recorded", rec.Verdict)
	}
}

// TestVerdict_HumanCarriesNoConfigRef: a human verdict records no config ref —
// the stamp is exclusively the AI dial's audit mark.
func TestVerdict_HumanCarriesNoConfigRef(t *testing.T) {
	env := newTestEnvelope("alice")
	st := activeState(env)
	st.Pins[uuid.New()] = true

	events, err := applyCommand(env, verdictCmd(), st)
	if err != nil {
		t.Fatalf("human verdict: %v", err)
	}
	rec := decodeInterp(t, events[0])
	if rec.Verdict == nil || rec.Verdict.Disposition != VerdictMalicious || rec.Verdict.ConfigRef != "" {
		t.Errorf("event verdict = %+v; want MALICIOUS with no config ref", rec.Verdict)
	}
}

// TestVerdict_FoldLatestWins: verdicts revise by appending; the disposition of
// record is the latest non-superseded act, and superseding it falls back to
// the prior one.
func TestVerdict_FoldLatestWins(t *testing.T) {
	v1, v2 := uuid.New(), uuid.New()
	s := aggregateState{
		Interpretations:   map[uuid.UUID]string{v1: InterpretationVerdict, v2: InterpretationVerdict},
		SupersededInterps: map[uuid.UUID]bool{},
		Pins:              map[uuid.UUID]bool{},
		Verdicts: []verdictEntry{
			{InterpID: v1, Disposition: VerdictSuspicious},
			{InterpID: v2, Disposition: VerdictMalicious},
		},
	}
	if got := s.CurrentVerdict(); got != VerdictMalicious {
		t.Fatalf("current verdict = %q; want the latest (MALICIOUS)", got)
	}
	foldSupersession(&s, InterpretationSupersededPayload{SupersededID: v2, SupersededType: InterpretationVerdict})
	if got := s.CurrentVerdict(); got != VerdictSuspicious {
		t.Fatalf("current verdict after supersession = %q; want the prior (SUSPICIOUS)", got)
	}
}

// TestSupersede_UnpinsAndGuards: superseding a pin deactivates it (the un-pin
// path); double-supersession, unknown targets, and transition-paired
// interpretations are all rejected.
func TestSupersede_UnpinsAndGuards(t *testing.T) {
	env := newTestEnvelope("alice")
	st := activeState(env)
	pinID, lifecycleID := uuid.New(), uuid.New()
	st.Interpretations[pinID] = InterpretationEvidencePin
	st.Interpretations[lifecycleID] = InterpretationLifecycle
	st.Pins[pinID] = true

	events, err := applyCommand(env, SupersedeInterpretation{SupersededID: pinID, Reason: "wrong host"}, st)
	if err != nil {
		t.Fatalf("supersede pin: %v", err)
	}
	if events[0].Type != EventTypeInterpretationSuperseded {
		t.Fatalf("event type = %q", events[0].Type)
	}

	// Fold it and confirm the pin is inactive (and the verdict gate would bite).
	var p InterpretationSupersededPayload
	mustUnmarshal(t, events[0].Payload, &p)
	foldSupersession(&st, p)
	if st.activePinCount() != 0 {
		t.Error("pin still active after supersession")
	}
	if _, err := applyCommand(env, verdictCmd(), st); err == nil {
		t.Error("verdict accepted with only a superseded pin")
	}

	if _, err := applyCommand(env, SupersedeInterpretation{SupersededID: pinID, Reason: "again"}, st); err == nil {
		t.Error("double supersession accepted")
	}
	if _, err := applyCommand(env, SupersedeInterpretation{SupersededID: uuid.New(), Reason: "r"}, st); err == nil {
		t.Error("superseding an unknown interpretation accepted")
	}
	if _, err := applyCommand(env, SupersedeInterpretation{SupersededID: lifecycleID, Reason: "r"}, st); err == nil {
		t.Error("superseding a lifecycle (transition-paired) interpretation accepted")
	}
}

// TestConclude_RequiresVerdict: the conclude gate, end to end at the pure
// layer — refused without a verdict, legal with one.
func TestConclude_RequiresVerdict(t *testing.T) {
	env := newTestEnvelope("alice")
	st := activeState(env)
	if _, err := applyCommand(env, ConcludeInvestigation{ReportRef: "r", Summary: "s"}, st); err == nil ||
		!strings.Contains(err.Error(), "no verdict of record") {
		t.Fatalf("conclude without verdict: err = %v; want the no-verdict rejection", err)
	}
	st.Verdicts = []verdictEntry{{InterpID: uuid.New(), Disposition: VerdictBenign}}
	if _, err := applyCommand(env, ConcludeInvestigation{ReportRef: "r", Summary: "s"}, st); err != nil {
		t.Fatalf("conclude with verdict: %v", err)
	}
}

// TestSeed_Validation: the three seed shapes and their required fields (01
// §Extension 1); an unknown type is rejected; seedless creation stays legal
// at the engine layer (the surface obligation is the picker's).
func TestSeed_Validation(t *testing.T) {
	env := newTestEnvelope("alice")
	cases := []struct {
		name string
		seed *Seed
		ok   bool
	}{
		{"nil seed", nil, true},
		{"alert", &Seed{Type: SeedAlert, AlertID: "EDR-7741", Source: "crowdstrike-edr"}, true},
		{"alert missing source", &Seed{Type: SeedAlert, AlertID: "EDR-7741"}, false},
		{"entity", &Seed{Type: SeedEntity, EntityRef: "x-host--00000000-0000-0000-0000-000000000001"}, true},
		{"entity missing ref", &Seed{Type: SeedEntity}, false},
		{"question", &Seed{Type: SeedQuestion, HypothesisStatement: "service accounts abused for RDP?"}, true},
		{"question empty", &Seed{Type: SeedQuestion}, false},
		{"case", &Seed{Type: SeedCase, CaseID: "INC0010001", Source: "servicenow"}, true},
		{"case missing source", &Seed{Type: SeedCase, CaseID: "INC0010001"}, false},
		{"case missing id", &Seed{Type: SeedCase, Source: "servicenow"}, false},
		{"unknown type", &Seed{Type: "vibes"}, false},
	}
	for _, tc := range cases {
		err := (CreateInvestigation{Title: "t", Seed: tc.seed}).Validate(env)
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: invalid seed accepted", tc.name)
		}
	}
}

// TestSeed_Summary: the triage line per shape.
func TestSeed_Summary(t *testing.T) {
	if got := (Seed{Type: SeedAlert, AlertID: "A-1", Source: "edr"}).Summary(); got != "edr: A-1" {
		t.Errorf("alert summary = %q", got)
	}
	if got := (Seed{Type: SeedEntity, EntityRef: "x-host--1"}).Summary(); got != "x-host--1" {
		t.Errorf("entity summary = %q", got)
	}
	if got := (Seed{Type: SeedQuestion, HypothesisStatement: "q?"}).Summary(); got != "q?" {
		t.Errorf("question summary = %q", got)
	}
	// A case seed carries the "case " prefix so the triage queue distinguishes it
	// from an alert without reading seed_type (14 §1).
	if got := (Seed{Type: SeedCase, CaseID: "INC0010001", Source: "servicenow"}).Summary(); got != "case servicenow: INC0010001" {
		t.Errorf("case summary = %q", got)
	}
}
