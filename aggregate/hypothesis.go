package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

// x-hypothesis status values (01-domain-model.md §x-hypothesis). Status is a
// projection over interpretation events, never stored aggregate state: a
// hypothesis is created PROPOSED (AI-authored) or OPEN (human-authored), a
// human acknowledgment moves PROPOSED→OPEN, and the evidential outcomes
// (support / refutation / inconclusive interpretations) terminate it. Terminal
// statuses accept no further transitions in v0 — a changed judgment is a new
// hypothesis (parent_ref chains the refinement).
const (
	HypothesisProposed     = "PROPOSED"
	HypothesisOpen         = "OPEN"
	HypothesisSupported    = "SUPPORTED"
	HypothesisRefuted      = "REFUTED"
	HypothesisInconclusive = "INCONCLUSIVE"
	HypothesisAbandoned    = "ABANDONED"
)

// x-prediction status values (01-domain-model.md §x-prediction). A prediction
// is created UNTESTED against a PROPOSED/OPEN hypothesis and terminates when
// its test outcome is recorded.
const (
	PredictionUntested     = "UNTESTED"
	PredictionConfirmed    = "CONFIRMED"
	PredictionDisconfirmed = "DISCONFIRMED"
	PredictionInconclusive = "INCONCLUSIVE"
)

// STIX type prefixes for the reasoning nodes (custom objects per the x- STIX
// convention, 01-domain-model.md §Adopted vs invented).
const (
	stixTypeHypothesis = "x-hypothesis"
	stixTypePrediction = "x-prediction"
)

// HypothesisSTIXID renders the canonical STIX id for a hypothesis uuid.
func HypothesisSTIXID(id uuid.UUID) string { return stixTypeHypothesis + "--" + id.String() }

// PredictionSTIXID renders the canonical STIX id for a prediction uuid.
func PredictionSTIXID(id uuid.UUID) string { return stixTypePrediction + "--" + id.String() }

// stixIDUUID extracts the uuid part of a `<type>--<uuid>` STIX id, checking the
// type prefix. Returns an error on any malformation.
func stixIDUUID(stixID, wantType string) (uuid.UUID, error) {
	rest, ok := strings.CutPrefix(stixID, wantType+"--")
	if !ok {
		return uuid.UUID{}, fmt.Errorf("%q is not a %s id", stixID, wantType)
	}
	id, err := uuid.Parse(rest)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("%q is not a %s id: %w", stixID, wantType, err)
	}
	return id, nil
}

// statementMaxRunes bounds the hypothesis/prediction statement — a claim, not
// an essay; supporting detail belongs in the rationale and transcript.
const statementMaxRunes = 1000

// maxLabels bounds the label list (ATT&CK technique ids by convention).
const maxLabels = 20

// Bounds on a prediction's declared test query — it lands in the event payload
// (and the STIX node), so it must stay a query spec, not a bulk carrier. The
// transcript side store is where large content belongs.
const (
	maxQueryTextRunes  = 4000
	maxQueryParamBytes = 4096
)

// HypothesisNode is the creation payload for a new x-hypothesis, carried on a
// RecordInterpretation of type "hypothesis" (01: hypotheses are OUTPUTS of
// interpretations, not separate primitives — there is no CreateHypothesis
// command). ID is minted by the caller (the endpoint), like RequestAction.
type HypothesisNode struct {
	ID          uuid.UUID `json:"id"`
	Statement   string    `json:"statement"`
	ParentRef   string    `json:"parent_ref,omitempty"`    // x-hypothesis-- id (refinement chain)
	RootedAtRef string    `json:"rooted_at_ref,omitempty"` // SCO id (anchor entity)
	Labels      []string  `json:"labels,omitempty"`        // ATT&CK technique ids by convention
}

// QuerySpec is a prediction's optional declared test (01 §x-prediction): what
// query against which tool would confirm or disconfirm it.
type QuerySpec struct {
	Tool       string         `json:"tool"`
	QueryText  string         `json:"query_text"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

// PredictionNode is the creation payload for a new x-prediction, carried on a
// RecordInterpretation of type "prediction".
type PredictionNode struct {
	ID            uuid.UUID  `json:"id"`
	HypothesisRef string     `json:"hypothesis_ref"`
	Statement     string     `json:"statement"`
	TestQuery     *QuerySpec `json:"test_query,omitempty"`
}

// --- event payload records ----------------------------------------------------

// HypothesisRecorded is the node content recorded on the interpretation event
// when a hypothesis is created. The projector materializes it into stix_objects
// and hypothesis_current; foldState folds its status for transition legality.
type HypothesisRecorded struct {
	ID          string   `json:"id"` // full STIX id
	Statement   string   `json:"statement"`
	Status      string   `json:"status"` // PROPOSED (AI-authored) | OPEN (human-authored)
	ParentRef   string   `json:"parent_ref,omitempty"`
	RootedAtRef string   `json:"rooted_at_ref,omitempty"`
	Labels      []string `json:"labels,omitempty"`
}

// HypothesisTransitionRecorded records a status move on an existing hypothesis
// (acknowledgment or evidential outcome).
type HypothesisTransitionRecorded struct {
	Ref  string `json:"ref"` // full STIX id
	From string `json:"from"`
	To   string `json:"to"`
}

// PredictionRecorded is the node content recorded when a prediction is created.
type PredictionRecorded struct {
	ID            string     `json:"id"` // full STIX id
	HypothesisRef string     `json:"hypothesis_ref"`
	Statement     string     `json:"statement"`
	Status        string     `json:"status"` // always UNTESTED at creation
	TestQuery     *QuerySpec `json:"test_query,omitempty"`
}

// PredictionTransitionRecorded records a prediction's test outcome.
type PredictionTransitionRecorded struct {
	Ref            string   `json:"ref"` // full STIX id
	From           string   `json:"from"`
	To             string   `json:"to"`
	TestResultRefs []string `json:"test_result_refs,omitempty"` // ObservedData / Sighting ids
}

// --- folded state ---------------------------------------------------------------

// hypothesisState / predictionState are the per-node folded state, keyed by full
// STIX id in aggregateState. Only what transition legality needs.
type hypothesisState struct {
	Status string
}

type predictionState struct {
	Status        string
	HypothesisRef string // parent — so an outcome can check the hypothesis is acknowledged
}

// foldReasoningEvent applies one interpretation.recorded event's node content to
// the folded maps. Interpretation events without node content (lifecycle,
// action-*, free-standing reasoning) are a no-op here.
func foldReasoningEvent(s *aggregateState, rec InterpretationRecorded) {
	if rec.Hypothesis != nil {
		s.Hypotheses[rec.Hypothesis.ID] = hypothesisState{Status: rec.Hypothesis.Status}
	}
	if rec.HypothesisTransition != nil {
		s.Hypotheses[rec.HypothesisTransition.Ref] = hypothesisState{Status: rec.HypothesisTransition.To}
	}
	if rec.Prediction != nil {
		s.Predictions[rec.Prediction.ID] = predictionState{Status: rec.Prediction.Status, HypothesisRef: rec.Prediction.HypothesisRef}
	}
	if rec.PredictionTransition != nil {
		prev := s.Predictions[rec.PredictionTransition.Ref]
		s.Predictions[rec.PredictionTransition.Ref] = predictionState{Status: rec.PredictionTransition.To, HypothesisRef: prev.HypothesisRef}
	}
}

// --- command validation (shape) -------------------------------------------------

// validateReasoningNodeShape runs the pure shape checks for the node payloads a
// RecordInterpretation may carry, per interpretation type. State-dependent
// legality (existence, current status) lives in applyReasoningNodes.
func validateReasoningNodeShape(c RecordInterpretation) error {
	// No smuggling: node payloads are only legal on the types that produce them.
	nodeBearing := map[string]bool{
		InterpretationHypothesis:   true,
		InterpretationSupport:      true,
		InterpretationRefutation:   true,
		InterpretationInconclusive: true,
		InterpretationPrediction:   true,
	}
	if !nodeBearing[c.InterpretationType] {
		if c.Hypothesis != nil || c.HypothesisRef != "" || c.Prediction != nil || c.PredictionRef != "" ||
			c.Abandoned || c.PredictionStatus != "" || len(c.TestResultRefs) > 0 {
			return fmt.Errorf("RecordInterpretation: type %q must not carry hypothesis/prediction payloads", c.InterpretationType)
		}
		return nil
	}

	switch c.InterpretationType {
	case InterpretationHypothesis:
		if c.Prediction != nil || c.PredictionRef != "" {
			return errors.New("RecordInterpretation: type hypothesis must not carry prediction payloads")
		}
		// Exactly one of: create (Hypothesis) or acknowledge (HypothesisRef).
		if (c.Hypothesis == nil) == (c.HypothesisRef == "") {
			return errors.New("RecordInterpretation: type hypothesis requires exactly one of hypothesis (create) or hypothesis_ref (acknowledge)")
		}
		if c.Hypothesis != nil {
			return validateHypothesisNode(*c.Hypothesis)
		}
		if _, err := stixIDUUID(c.HypothesisRef, stixTypeHypothesis); err != nil {
			return fmt.Errorf("RecordInterpretation: %w", err)
		}
	case InterpretationSupport, InterpretationRefutation, InterpretationInconclusive:
		if c.HypothesisRef == "" {
			return fmt.Errorf("RecordInterpretation: type %s requires hypothesis_ref", c.InterpretationType)
		}
		if _, err := stixIDUUID(c.HypothesisRef, stixTypeHypothesis); err != nil {
			return fmt.Errorf("RecordInterpretation: %w", err)
		}
		if c.Hypothesis != nil || c.Prediction != nil || c.PredictionRef != "" {
			return fmt.Errorf("RecordInterpretation: type %s carries only hypothesis_ref", c.InterpretationType)
		}
		if c.Abandoned && c.InterpretationType != InterpretationInconclusive {
			return errors.New("RecordInterpretation: abandoned is only valid on type inconclusive")
		}
	case InterpretationPrediction:
		if c.Hypothesis != nil || c.HypothesisRef != "" {
			return errors.New("RecordInterpretation: type prediction must not carry hypothesis payloads")
		}
		// Exactly one of: create (Prediction) or record outcome (PredictionRef).
		if (c.Prediction == nil) == (c.PredictionRef == "") {
			return errors.New("RecordInterpretation: type prediction requires exactly one of prediction (create) or prediction_ref (outcome)")
		}
		if c.Prediction != nil {
			if c.PredictionStatus != "" || len(c.TestResultRefs) > 0 {
				return errors.New("RecordInterpretation: a prediction create carries no outcome fields")
			}
			return validatePredictionNode(*c.Prediction)
		}
		if _, err := stixIDUUID(c.PredictionRef, stixTypePrediction); err != nil {
			return fmt.Errorf("RecordInterpretation: %w", err)
		}
		switch c.PredictionStatus {
		case PredictionConfirmed, PredictionDisconfirmed:
			// The decisive outcomes must cite what was observed (04 §1's
			// evidence discipline): a confirmation with nothing observed is a
			// claim, not a test result.
			if len(c.TestResultRefs) == 0 {
				return fmt.Errorf("RecordInterpretation: prediction outcome %s requires test_result_refs", c.PredictionStatus)
			}
		case PredictionInconclusive:
		default:
			return fmt.Errorf("RecordInterpretation: invalid prediction outcome %q", c.PredictionStatus)
		}
		if len(c.TestResultRefs) > maxRefsPerInterpretation {
			return fmt.Errorf("RecordInterpretation: test_result_refs exceed %d", maxRefsPerInterpretation)
		}
	}

	// Abandoned only rides on inconclusive.
	if c.Abandoned && c.InterpretationType != InterpretationInconclusive {
		return errors.New("RecordInterpretation: abandoned is only valid on type inconclusive")
	}
	return nil
}

func validateHypothesisNode(h HypothesisNode) error {
	if h.ID == (uuid.UUID{}) {
		return errors.New("RecordInterpretation: hypothesis.id is zero")
	}
	if strings.TrimSpace(h.Statement) == "" {
		return errors.New("RecordInterpretation: hypothesis.statement is required")
	}
	if utf8.RuneCountInString(h.Statement) > statementMaxRunes {
		return fmt.Errorf("RecordInterpretation: hypothesis.statement exceeds %d chars", statementMaxRunes)
	}
	if h.ParentRef != "" {
		if _, err := stixIDUUID(h.ParentRef, stixTypeHypothesis); err != nil {
			return fmt.Errorf("RecordInterpretation: parent_ref: %w", err)
		}
	}
	if len(h.Labels) > maxLabels {
		return fmt.Errorf("RecordInterpretation: hypothesis labels exceed %d", maxLabels)
	}
	if err := validateRefList("labels", h.Labels); err != nil {
		return err
	}
	if h.RootedAtRef != "" {
		if err := validateRefList("rooted_at_ref", []string{h.RootedAtRef}); err != nil {
			return err
		}
	}
	return nil
}

func validatePredictionNode(p PredictionNode) error {
	if p.ID == (uuid.UUID{}) {
		return errors.New("RecordInterpretation: prediction.id is zero")
	}
	if _, err := stixIDUUID(p.HypothesisRef, stixTypeHypothesis); err != nil {
		return fmt.Errorf("RecordInterpretation: prediction.hypothesis_ref: %w", err)
	}
	if strings.TrimSpace(p.Statement) == "" {
		return errors.New("RecordInterpretation: prediction.statement is required")
	}
	if utf8.RuneCountInString(p.Statement) > statementMaxRunes {
		return fmt.Errorf("RecordInterpretation: prediction.statement exceeds %d chars", statementMaxRunes)
	}
	// The test query lands in the event payload — bound it (the transcript
	// side store is where bulk belongs).
	if q := p.TestQuery; q != nil {
		if utf8.RuneCountInString(q.QueryText) > maxQueryTextRunes {
			return fmt.Errorf("RecordInterpretation: test_query.query_text exceeds %d chars", maxQueryTextRunes)
		}
		if len(q.Parameters) > 0 {
			raw, err := json.Marshal(q.Parameters)
			if err != nil {
				return fmt.Errorf("RecordInterpretation: test_query.parameters: %w", err)
			}
			if len(raw) > maxQueryParamBytes {
				return fmt.Errorf("RecordInterpretation: test_query.parameters exceed %d bytes", maxQueryParamBytes)
			}
		}
	}
	return nil
}

// --- apply (state-dependent legality + event enrichment) -------------------------

// applyReasoningNodes validates a node-bearing interpretation against folded
// state and enriches the InterpretationRecorded payload with the node content
// the projector materializes. Returns nil for types that carry no nodes.
func applyReasoningNodes(env Envelope, state aggregateState, c RecordInterpretation, rec *InterpretationRecorded) error {
	switch c.InterpretationType {
	case InterpretationHypothesis:
		if c.Hypothesis != nil {
			return applyHypothesisCreate(env, state, *c.Hypothesis, rec)
		}
		return applyHypothesisAck(env, state, c.HypothesisRef, rec)
	case InterpretationSupport:
		return applyHypothesisOutcome(env, state, c.HypothesisRef, HypothesisSupported, c, rec)
	case InterpretationRefutation:
		return applyHypothesisOutcome(env, state, c.HypothesisRef, HypothesisRefuted, c, rec)
	case InterpretationInconclusive:
		to := HypothesisInconclusive
		if c.Abandoned {
			to = HypothesisAbandoned
		}
		return applyHypothesisOutcome(env, state, c.HypothesisRef, to, c, rec)
	case InterpretationPrediction:
		if c.Prediction != nil {
			return applyPredictionCreate(state, *c.Prediction, rec)
		}
		return applyPredictionOutcome(env, state, c, rec)
	default:
		return nil
	}
}

func applyHypothesisCreate(env Envelope, state aggregateState, h HypothesisNode, rec *InterpretationRecorded) error {
	stixID := HypothesisSTIXID(h.ID)
	if _, exists := state.Hypotheses[stixID]; exists {
		return fmt.Errorf("RecordInterpretation rejected: hypothesis %s already exists", stixID)
	}
	// A refinement must chain to a real parent in this investigation.
	if h.ParentRef != "" {
		if _, ok := state.Hypotheses[h.ParentRef]; !ok {
			return fmt.Errorf("RecordInterpretation rejected: parent hypothesis %s does not exist", h.ParentRef)
		}
	}
	// AI-authored hypotheses arrive PROPOSED and await a human acknowledgment;
	// human-authored ones are OPEN immediately (01 §Interpretation types:
	// "AI-PROPOSED → OPEN acknowledgment").
	status := HypothesisOpen
	if env.Actor.IsAIDelegated() {
		status = HypothesisProposed
	}
	rec.Hypothesis = &HypothesisRecorded{
		ID:          stixID,
		Statement:   h.Statement,
		Status:      status,
		ParentRef:   h.ParentRef,
		RootedAtRef: h.RootedAtRef,
		Labels:      h.Labels,
	}
	rec.OutputRefs = append(rec.OutputRefs, stixID)
	return nil
}

func applyHypothesisAck(env Envelope, state aggregateState, ref string, rec *InterpretationRecorded) error {
	hs, ok := state.Hypotheses[ref]
	if !ok {
		return fmt.Errorf("RecordInterpretation rejected: hypothesis %s does not exist", ref)
	}
	if hs.Status != HypothesisProposed {
		return fmt.Errorf("RecordInterpretation rejected: hypothesis %s is %s, only PROPOSED can be acknowledged", ref, hs.Status)
	}
	// Acknowledging an AI-proposed hypothesis is the human taking ownership of
	// the line of inquiry — an AI delegate cannot acknowledge (its own, or any)
	// proposal into OPEN.
	if env.Actor.IsAIDelegated() {
		return errors.New("RecordInterpretation rejected: acknowledging a hypothesis is a human act")
	}
	rec.HypothesisTransition = &HypothesisTransitionRecorded{Ref: ref, From: hs.Status, To: HypothesisOpen}
	rec.OutputRefs = append(rec.OutputRefs, ref)
	return nil
}

// aiReasoningGate enforces the human-in-the-loop rung (01 §Interpretation types,
// "AI-PROPOSED → OPEN acknowledgment"): an AI delegate may not record an
// evidential OUTCOME — a prediction result or a hypothesis evaluation — on a
// hypothesis that is still PROPOSED (never human-acknowledged). A human passes
// freely (engaging with an AI proposal is itself the human taking the loop), and
// an OPEN hypothesis passes freely. The tenant dial trust.ai_reasoning reopens
// full automation: the server stamps AIReasoningConfigRef only when it is on, so
// absent stamp + AI actor + PROPOSED = denied on every path (structural
// default-deny, mirroring the AI-verdict dial).
func aiReasoningGate(env Envelope, c RecordInterpretation, hypStatus string) error {
	if hypStatus != HypothesisProposed || !env.Actor.IsAIDelegated() {
		return nil
	}
	if c.AIReasoningConfigRef == "" {
		return errors.New("RecordInterpretation rejected: an AI delegate cannot record an outcome on an unacknowledged (PROPOSED) hypothesis — a human must Acknowledge it first, or enable the tenant dial trust.ai_reasoning")
	}
	return nil
}

func applyHypothesisOutcome(env Envelope, state aggregateState, ref, to string, c RecordInterpretation, rec *InterpretationRecorded) error {
	hs, ok := state.Hypotheses[ref]
	if !ok {
		return fmt.Errorf("RecordInterpretation rejected: hypothesis %s does not exist", ref)
	}
	// Only a live hypothesis (PROPOSED or OPEN) takes an evidential outcome;
	// terminal statuses are terminal in v0 — a changed judgment is a new
	// hypothesis chained via parent_ref, keeping every reversal auditable.
	if hs.Status != HypothesisProposed && hs.Status != HypothesisOpen {
		return fmt.Errorf("RecordInterpretation rejected: hypothesis %s is %s (terminal), cannot move to %s", ref, hs.Status, to)
	}
	if err := aiReasoningGate(env, c, hs.Status); err != nil {
		return err
	}
	rec.HypothesisTransition = &HypothesisTransitionRecorded{Ref: ref, From: hs.Status, To: to}
	rec.OutputRefs = append(rec.OutputRefs, ref)
	return nil
}

func applyPredictionCreate(state aggregateState, p PredictionNode, rec *InterpretationRecorded) error {
	stixID := PredictionSTIXID(p.ID)
	if _, exists := state.Predictions[stixID]; exists {
		return fmt.Errorf("RecordInterpretation rejected: prediction %s already exists", stixID)
	}
	hs, ok := state.Hypotheses[p.HypothesisRef]
	if !ok {
		return fmt.Errorf("RecordInterpretation rejected: hypothesis %s does not exist", p.HypothesisRef)
	}
	// Predictions exist to test undecided hypotheses.
	if hs.Status != HypothesisProposed && hs.Status != HypothesisOpen {
		return fmt.Errorf("RecordInterpretation rejected: hypothesis %s is %s, predictions test PROPOSED/OPEN hypotheses", p.HypothesisRef, hs.Status)
	}
	rec.Prediction = &PredictionRecorded{
		ID:            stixID,
		HypothesisRef: p.HypothesisRef,
		Statement:     p.Statement,
		Status:        PredictionUntested,
		TestQuery:     p.TestQuery,
	}
	rec.OutputRefs = append(rec.OutputRefs, stixID)
	return nil
}

func applyPredictionOutcome(env Envelope, state aggregateState, c RecordInterpretation, rec *InterpretationRecorded) error {
	ps, ok := state.Predictions[c.PredictionRef]
	if !ok {
		return fmt.Errorf("RecordInterpretation rejected: prediction %s does not exist", c.PredictionRef)
	}
	if ps.Status != PredictionUntested {
		return fmt.Errorf("RecordInterpretation rejected: prediction %s is %s, only UNTESTED takes an outcome", c.PredictionRef, ps.Status)
	}
	// Running a test is an evidential outcome — gated on the parent hypothesis
	// being human-acknowledged when the actor is an AI delegate.
	if err := aiReasoningGate(env, c, state.Hypotheses[ps.HypothesisRef].Status); err != nil {
		return err
	}
	rec.PredictionTransition = &PredictionTransitionRecorded{
		Ref:            c.PredictionRef,
		From:           ps.Status,
		To:             c.PredictionStatus,
		TestResultRefs: c.TestResultRefs,
	}
	rec.OutputRefs = append(rec.OutputRefs, c.PredictionRef)
	return nil
}
