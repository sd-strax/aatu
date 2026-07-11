package aggregate

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// reasoningState builds an ACTIVE aggregateState carrying the given node maps.
func reasoningState(hyps map[string]hypothesisState, preds map[string]predictionState) aggregateState {
	if hyps == nil {
		hyps = map[string]hypothesisState{}
	}
	if preds == nil {
		preds = map[string]predictionState{}
	}
	return aggregateState{
		Seq: 4, Exists: true, TenantID: testTenantID, Status: StatusActive,
		Actions: map[uuid.UUID]actionState{}, Hypotheses: hyps, Predictions: preds,
	}
}

// recFromEvents unmarshals the single emitted interpretation event's payload.
func recFromEvents(t *testing.T, events []Event) InterpretationRecorded {
	t.Helper()
	if len(events) != 1 || events[0].Type != EventTypeInterpretationRecorded {
		t.Fatalf("expected one interpretation.recorded event, got %+v", events)
	}
	var rec InterpretationRecorded
	if err := json.Unmarshal(events[0].Payload, &rec); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return rec
}

// TestReasoningNodeShape_Validate covers the pure shape guards: payload
// smuggling on non-node types, the create-XOR-ref rules, outcome evidence
// requirements, and the abandoned flag's home.
func TestReasoningNodeShape_Validate(t *testing.T) {
	env := newTestEnvelope("analyst-1")
	base := RecordInterpretation{
		InterpretationID: uuid.New(),
		Rationale:        "because evidence",
	}

	// A non-node type must not carry node payloads.
	pivot := base
	pivot.InterpretationType = InterpretationPivot
	pivot.Hypothesis = &HypothesisNode{ID: uuid.New(), Statement: "x"}
	if err := pivot.Validate(env); err == nil {
		t.Error("pivot carrying a hypothesis payload accepted")
	}
	pivot.Hypothesis = nil
	pivot.PredictionStatus = PredictionConfirmed
	if err := pivot.Validate(env); err == nil {
		t.Error("pivot carrying a prediction outcome accepted")
	}

	// hypothesis: create XOR acknowledge.
	hyp := base
	hyp.InterpretationType = InterpretationHypothesis
	if err := hyp.Validate(env); err == nil {
		t.Error("type hypothesis with neither create nor ref accepted")
	}
	hyp.Hypothesis = &HypothesisNode{ID: uuid.New(), Statement: "claim"}
	hyp.HypothesisRef = HypothesisSTIXID(uuid.New())
	if err := hyp.Validate(env); err == nil {
		t.Error("type hypothesis with both create and ref accepted")
	}

	// Create requires a statement.
	noStmt := base
	noStmt.InterpretationType = InterpretationHypothesis
	noStmt.Hypothesis = &HypothesisNode{ID: uuid.New()}
	if err := noStmt.Validate(env); err == nil {
		t.Error("hypothesis without statement accepted")
	}

	// support requires a well-formed hypothesis ref.
	sup := base
	sup.InterpretationType = InterpretationSupport
	sup.HypothesisRef = "x-action--" + uuid.NewString() // wrong type prefix
	if err := sup.Validate(env); err == nil {
		t.Error("support with a non-hypothesis ref accepted")
	}

	// abandoned only rides on inconclusive.
	sup.HypothesisRef = HypothesisSTIXID(uuid.New())
	sup.Abandoned = true
	if err := sup.Validate(env); err == nil {
		t.Error("abandoned on type support accepted")
	}

	// A decisive prediction outcome must cite test results.
	out := base
	out.InterpretationType = InterpretationPrediction
	out.PredictionRef = PredictionSTIXID(uuid.New())
	out.PredictionStatus = PredictionConfirmed
	if err := out.Validate(env); err == nil {
		t.Error("CONFIRMED outcome without test_result_refs accepted")
	}
	out.TestResultRefs = []string{"observed-data--1"}
	if err := out.Validate(env); err != nil {
		t.Errorf("valid CONFIRMED outcome rejected: %v", err)
	}
	out.PredictionStatus = "MAYBE"
	if err := out.Validate(env); err == nil {
		t.Error("invalid prediction outcome vocabulary accepted")
	}
}

// TestHypothesisLifecycle_Apply covers the state machine at the pure layer:
// authorship-derived initial status, the human-only acknowledgment, evidential
// outcomes from live statuses only, and refinement chaining.
func TestHypothesisLifecycle_Apply(t *testing.T) {
	human := newTestEnvelope("analyst-1")
	ai := newTestEnvelope("analyst-1")
	ai.Actor.Kind = ActorAIDelegated
	ai.Actor.Delegate = &AIDelegate{Vendor: "claude"}

	// AI-authored → PROPOSED; human-authored → OPEN.
	mk := func(id uuid.UUID) RecordInterpretation {
		return RecordInterpretation{
			InterpretationID:   uuid.New(),
			InterpretationType: InterpretationHypothesis,
			Rationale:          "beaconing",
			Hypothesis:         &HypothesisNode{ID: id, Statement: "C2 via DNS"},
		}
	}
	aiEvents, err := applyCommand(ai, mk(uuid.New()), reasoningState(nil, nil))
	if err != nil {
		t.Fatalf("AI create: %v", err)
	}
	if rec := recFromEvents(t, aiEvents); rec.Hypothesis.Status != HypothesisProposed {
		t.Errorf("AI-authored status = %q; want PROPOSED", rec.Hypothesis.Status)
	}
	humanEvents, err := applyCommand(human, mk(uuid.New()), reasoningState(nil, nil))
	if err != nil {
		t.Fatalf("human create: %v", err)
	}
	rec := recFromEvents(t, humanEvents)
	if rec.Hypothesis.Status != HypothesisOpen {
		t.Errorf("human-authored status = %q; want OPEN", rec.Hypothesis.Status)
	}
	// The created node id is recorded as an output ref.
	if len(rec.OutputRefs) != 1 || rec.OutputRefs[0] != rec.Hypothesis.ID {
		t.Errorf("output_refs = %v; want [%s]", rec.OutputRefs, rec.Hypothesis.ID)
	}

	// A refinement's parent must exist.
	orphan := mk(uuid.New())
	orphan.Hypothesis.ParentRef = HypothesisSTIXID(uuid.New())
	if _, err := applyCommand(human, orphan, reasoningState(nil, nil)); err == nil {
		t.Error("refinement with nonexistent parent accepted")
	}

	// Acknowledgment: PROPOSED only, human only.
	ref := HypothesisSTIXID(uuid.New())
	proposed := func() aggregateState {
		return reasoningState(map[string]hypothesisState{ref: {Status: HypothesisProposed}}, nil)
	}
	ack := RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationHypothesis,
		Rationale:          "worth pursuing",
		HypothesisRef:      ref,
	}
	if _, err := applyCommand(ai, ack, proposed()); err == nil {
		t.Error("AI acknowledgment accepted (human act)")
	}
	ackEvents, err := applyCommand(human, ack, proposed())
	if err != nil {
		t.Fatalf("human ack: %v", err)
	}
	if tr := recFromEvents(t, ackEvents).HypothesisTransition; tr == nil || tr.From != HypothesisProposed || tr.To != HypothesisOpen {
		t.Errorf("ack transition = %+v; want PROPOSED→OPEN", tr)
	}

	// Evidential outcome from OPEN; terminal statuses take no further moves.
	open := reasoningState(map[string]hypothesisState{ref: {Status: HypothesisOpen}}, nil)
	sup := RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationSupport,
		Rationale:          "three confirmed predictions",
		HypothesisRef:      ref,
	}
	supEvents, err := applyCommand(ai, sup, open)
	if err != nil {
		t.Fatalf("support: %v", err)
	}
	if tr := recFromEvents(t, supEvents).HypothesisTransition; tr.To != HypothesisSupported {
		t.Errorf("support transition to %q; want SUPPORTED", tr.To)
	}
	terminal := reasoningState(map[string]hypothesisState{ref: {Status: HypothesisSupported}}, nil)
	if _, err := applyCommand(human, sup, terminal); err == nil {
		t.Error("outcome on a terminal hypothesis accepted")
	}

	// inconclusive routes to INCONCLUSIVE, or ABANDONED with the flag.
	inc := sup
	inc.InterpretationType = InterpretationInconclusive
	inc.Abandoned = true
	incEvents, err := applyCommand(human, inc, reasoningState(map[string]hypothesisState{ref: {Status: HypothesisOpen}}, nil))
	if err != nil {
		t.Fatalf("inconclusive/abandoned: %v", err)
	}
	if tr := recFromEvents(t, incEvents).HypothesisTransition; tr.To != HypothesisAbandoned {
		t.Errorf("abandoned transition to %q; want ABANDONED", tr.To)
	}
}

// TestPredictionLifecycle_Apply covers prediction creation (live hypotheses
// only) and the once-only test outcome.
func TestPredictionLifecycle_Apply(t *testing.T) {
	env := newTestEnvelope("analyst-1")
	hRef := HypothesisSTIXID(uuid.New())

	mk := func(hyp string) RecordInterpretation {
		return RecordInterpretation{
			InterpretationID:   uuid.New(),
			InterpretationType: InterpretationPrediction,
			Rationale:          "if true, we'd see this",
			Prediction:         &PredictionNode{ID: uuid.New(), HypothesisRef: hyp, Statement: "outbound 53/udp spikes"},
		}
	}

	// Hypothesis must exist and be live.
	if _, err := applyCommand(env, mk(hRef), reasoningState(nil, nil)); err == nil {
		t.Error("prediction against nonexistent hypothesis accepted")
	}
	refuted := reasoningState(map[string]hypothesisState{hRef: {Status: HypothesisRefuted}}, nil)
	if _, err := applyCommand(env, mk(hRef), refuted); err == nil {
		t.Error("prediction against a terminal hypothesis accepted")
	}
	open := reasoningState(map[string]hypothesisState{hRef: {Status: HypothesisOpen}}, nil)
	events, err := applyCommand(env, mk(hRef), open)
	if err != nil {
		t.Fatalf("prediction create: %v", err)
	}
	rec := recFromEvents(t, events)
	if rec.Prediction == nil || rec.Prediction.Status != PredictionUntested {
		t.Fatalf("prediction = %+v; want UNTESTED", rec.Prediction)
	}

	// Outcome: UNTESTED only, once.
	pRef := rec.Prediction.ID
	outcome := RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: InterpretationPrediction,
		Rationale:          "query returned matches",
		PredictionRef:      pRef,
		PredictionStatus:   PredictionConfirmed,
		TestResultRefs:     []string{"observed-data--1"},
	}
	untested := reasoningState(
		map[string]hypothesisState{hRef: {Status: HypothesisOpen}},
		map[string]predictionState{pRef: {Status: PredictionUntested}},
	)
	outEvents, err := applyCommand(env, outcome, untested)
	if err != nil {
		t.Fatalf("outcome: %v", err)
	}
	if tr := recFromEvents(t, outEvents).PredictionTransition; tr.To != PredictionConfirmed || len(tr.TestResultRefs) != 1 {
		t.Errorf("outcome transition = %+v; want CONFIRMED with refs", tr)
	}
	tested := reasoningState(
		map[string]hypothesisState{hRef: {Status: HypothesisOpen}},
		map[string]predictionState{pRef: {Status: PredictionConfirmed}},
	)
	if _, err := applyCommand(env, outcome, tested); err == nil {
		t.Error("second outcome on a tested prediction accepted")
	}
}

// TestReasoningNodes_ProjectionAndReplay drives the full flow through the
// handler and verifies both stores (stix_objects + *_current) materialize in
// the same commits — then rebuilds everything via Replay and checks the nodes
// survive identically (the projector is a pure function of the event log).
func TestReasoningNodes_ProjectionAndReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetTables(t)
	ctx := context.Background()
	tenantID := uuid.New()
	h := newTestHandler()
	invID := activeInvestigation(t, h, tenantID)

	env := func(kind string) Envelope {
		e := Envelope{
			AggregateID: invID, TenantID: tenantID, CorrelationID: uuid.New(),
			Actor: Actor{PrincipalID: "analyst-1", Kind: kind}, OccurredAt: newTestEnvelope("").OccurredAt,
		}
		if kind == ActorAIDelegated {
			e.Actor.Delegate = &AIDelegate{Vendor: "claude"}
		}
		return e
	}
	mustHandle := func(e Envelope, cmd Command) Result {
		t.Helper()
		res, err := h.Handle(ctx, e, cmd)
		if err != nil {
			t.Fatalf("%s: %v", cmd.Kind(), err)
		}
		return res
	}

	// AI proposes → human acknowledges → prediction → CONFIRMED → SUPPORTED.
	hypID := uuid.New()
	mustHandle(env(ActorAIDelegated), RecordInterpretation{
		InterpretationID: uuid.New(), InterpretationType: InterpretationHypothesis,
		Rationale:  "beaconing pattern",
		Hypothesis: &HypothesisNode{ID: hypID, Statement: "C2 via DNS tunneling", Labels: []string{"T1071.004"}},
	})
	hRef := HypothesisSTIXID(hypID)
	mustHandle(env(""), RecordInterpretation{
		InterpretationID: uuid.New(), InterpretationType: InterpretationHypothesis,
		Rationale: "worth pursuing", HypothesisRef: hRef,
	})
	predID := uuid.New()
	mustHandle(env(ActorAIDelegated), RecordInterpretation{
		InterpretationID: uuid.New(), InterpretationType: InterpretationPrediction,
		Rationale:  "if tunneling, TXT volume spikes",
		Prediction: &PredictionNode{ID: predID, HypothesisRef: hRef, Statement: "anomalous TXT query volume from WIN-A"},
	})
	pRef := PredictionSTIXID(predID)
	mustHandle(env(ActorAIDelegated), RecordInterpretation{
		InterpretationID: uuid.New(), InterpretationType: InterpretationPrediction,
		Rationale: "query confirmed the spike", PredictionRef: pRef,
		PredictionStatus: PredictionConfirmed, TestResultRefs: []string{"observed-data--1"},
	})
	mustHandle(env(ActorAIDelegated), RecordInterpretation{
		InterpretationID: uuid.New(), InterpretationType: InterpretationSupport,
		Rationale: "prediction confirmed", HypothesisRef: hRef,
	})

	verify := func(phase string) {
		t.Helper()
		hs, err := ListHypotheses(ctx, testDB, invID)
		if err != nil || len(hs) != 1 {
			t.Fatalf("[%s] ListHypotheses = %v, %v; want 1", phase, hs, err)
		}
		if hs[0].ID != hRef || hs[0].Status != HypothesisSupported || len(hs[0].Labels) != 1 {
			t.Errorf("[%s] hypothesis = %+v; want %s SUPPORTED with 1 label", phase, hs[0], hRef)
		}
		ps, err := ListPredictions(ctx, testDB, invID)
		if err != nil || len(ps) != 1 {
			t.Fatalf("[%s] ListPredictions = %v, %v; want 1", phase, ps, err)
		}
		if ps[0].Status != PredictionConfirmed || len(ps[0].TestResultRefs) != 1 {
			t.Errorf("[%s] prediction = %+v; want CONFIRMED with refs", phase, ps[0])
		}

		// The canonical STIX node: status transitioned in-place, id intact.
		var payload []byte
		if err := testDB.QueryRow(`SELECT payload FROM stix_objects WHERE id = $1`, hypID).Scan(&payload); err != nil {
			t.Fatalf("[%s] stix x-hypothesis row: %v", phase, err)
		}
		var node map[string]any
		_ = json.Unmarshal(payload, &node)
		if node["type"] != "x-hypothesis" || node["id"] != hRef || node["status"] != HypothesisSupported {
			t.Errorf("[%s] stix node = %v; want x-hypothesis %s SUPPORTED", phase, node, hRef)
		}
		if err := testDB.QueryRow(`SELECT payload FROM stix_objects WHERE id = $1`, predID).Scan(&payload); err != nil {
			t.Fatalf("[%s] stix x-prediction row: %v", phase, err)
		}
		_ = json.Unmarshal(payload, &node)
		if node["status"] != PredictionConfirmed {
			t.Errorf("[%s] stix prediction status = %v; want CONFIRMED", phase, node["status"])
		}
	}
	verify("live")

	// Replay rebuilds the nodes from the event log alone.
	if err := h.Replay(ctx); err != nil {
		t.Fatalf("replay: %v", err)
	}
	verify("replayed")
}
