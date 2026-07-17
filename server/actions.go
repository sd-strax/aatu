package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/temporal"
)

// RequestActionBody is the request_action tool call over HTTP (08 §2).
type RequestActionBody struct {
	ActionType       string                 `json:"action_type"`
	Targets          []aggregate.TargetSpec `json:"targets"`
	Parameters       json.RawMessage        `json:"parameters,omitempty"`
	EvidenceRefs     []string               `json:"evidence_refs,omitempty"`
	Rationale        string                 `json:"rationale"`
	InvestigationRef string                 `json:"investigation_ref"`
	// ReversalOfRef, when set, makes this request a reversal of that original
	// action (04 §7): action_type should be the inverse, and auto-approval
	// triggers the ReversalSaga instead of a plain dispatch.
	ReversalOfRef string `json:"reversal_of_ref,omitempty"`
}

// RequestActionResponse reports the created x-action and how authorization
// resolved.
type RequestActionResponse struct {
	ActionID         string `json:"action_id"`
	Tier             string `json:"tier"`
	Status           string `json:"status"` // PENDING_MANUAL | PENDING_TWO_PARTY | APPROVED
	Mode             string `json:"mode"`
	MatchedPolicyRef string `json:"matched_policy_ref,omitempty"`
	WorkflowID       string `json:"workflow_id,omitempty"`
}

// ActionView is one row of GET /api/investigations/{id}/actions — the action
// review queue + audit list a surface renders to offer approvals. Status is the
// projection's raw lifecycle status (REQUESTED/PENDING_SECONDARY/APPROVED/…);
// required_mode says what approval the request still needs (MANUAL/TWO_PARTY).
type ActionView struct {
	ActionID     string                 `json:"action_id"`
	ActionType   string                 `json:"action_type"`
	Tier         string                 `json:"tier"`
	Status       string                 `json:"status"`
	RequiredMode string                 `json:"required_mode,omitempty"`
	Mode         string                 `json:"mode,omitempty"`
	IsReversal   bool                   `json:"is_reversal,omitempty"`
	Targets      []aggregate.TargetSpec `json:"targets,omitempty"`
	EvidenceRefs []string               `json:"evidence_refs,omitempty"`
	ExpiresAt    *time.Time             `json:"expires_at,omitempty"`
}

// listInvestigationActions serves GET /api/investigations/{id}/actions: every
// x-action of the investigation, oldest first. This is how a surface recovers
// the pending-approval queue after the turn that proposed an action is gone —
// the request-time response is a one-shot; this list is the durable view.
func (b *Backend) listInvestigationActions(w http.ResponseWriter, r *http.Request) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "aggregate handler not configured")
		return
	}
	invID, ok := investigationSubresourceID(r.URL.Path, "actions")
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid investigation id in path")
		return
	}

	acts, err := aggregate.ListActionCurrents(r.Context(), b.cfg.Handler.DB(), invID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list actions: "+err.Error())
		return
	}
	out := make([]ActionView, 0, len(acts))
	for _, a := range acts {
		v := ActionView{
			ActionID:     a.ActionID.String(),
			ActionType:   a.ActionType,
			Tier:         a.Tier,
			Status:       a.Status,
			RequiredMode: a.RequiredMode,
			Mode:         a.Mode,
			IsReversal:   a.IsReversal,
			Targets:      a.Targets,
			EvidenceRefs: a.EvidenceRefs,
		}
		if !a.ExpiresAt.IsZero() {
			t := a.ExpiresAt
			v.ExpiresAt = &t
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": out})
}

// listActionTypes serves GET /api/action-types: the write-side catalog with
// per-type dispatchability (08 §3), the symmetric twin of GET /api/capabilities.
// This is how the agent learns the real, frozen action vocabulary (host.isolate,
// ioc.block, …) with intents and tiers, instead of guessing action_type strings.
// Any authenticated reader.
func (b *Backend) listActionTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	if b.cfg.ActionCatalog == nil || b.cfg.ActionResolver == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "action layer not configured")
		return
	}
	b.requireRolesOrDeny(w, r, []string{authz.RoleViewer, authz.RoleAnalyst, authz.RoleAuditor}, func(w http.ResponseWriter, _ *http.Request) {
		summaries := b.cfg.ActionResolver.ListActionTypes(b.cfg.ActionCatalog)
		writeJSON(w, http.StatusOK, map[string]any{"action_types": summaries})
	})
}

// actorFromClaims derives the command actor from the JWT claims — Kind from the
// delegate_kind claim, NEVER a request body (04 §5.6): otherwise the AI
// write-protection at the aggregate boundary is caller-spoofable. Every handler
// that issues commands uses this ONE derivation, so the aggregate's allowlist
// is a real second layer behind any endpoint-level delegate check.
func actorFromClaims(c authz.Claims) aggregate.Actor {
	if c.DelegateKind != "" {
		return aggregate.Actor{
			PrincipalID: c.Subject,
			Kind:        aggregate.ActorAIDelegated,
			Delegate:    &aggregate.AIDelegate{Vendor: c.DelegateKind},
		}
	}
	return aggregate.Actor{PrincipalID: c.Subject, Kind: aggregate.ActorHuman}
}

// actionsCollection routes /api/actions. POST (request_action) requires the
// analyst role — the AI proposes on an analyst's behalf, never as a principal.
func (b *Backend) actionsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.requestAction)
	default:
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// requestAction handles POST /api/actions: the agent-facing request_action tool
// (08 §2). It builds the x-action, runs Gate 2 (04 §4), records the request +
// policy evaluation in one transaction, and — on auto-approval — approves and
// triggers the ActionLifecycle workflow. Requires the analyst role (the AI
// proposes on an analyst's behalf; the AI is never a principal).
func (b *Backend) requestAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if b.cfg.Handler == nil || b.cfg.Gate2 == nil || b.cfg.ActionCatalog == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "action layer not configured")
		return
	}
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth context missing")
		return
	}

	var body RequestActionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	investigationID, err := uuid.Parse(body.InvestigationRef)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "investigation_ref is not a valid id")
		return
	}

	actor := actorFromClaims(claims)
	now := commandNow()

	// A reversal targets an original action id. Validate it BEFORE anything
	// else (04 §7): the original must exist and be SUCCEEDED (you can only
	// reverse an action that took effect), and the requested action_type must
	// be the original descriptor's declared inverse — otherwise the eventual
	// action.reversed would claim an undo that never happened.
	var (
		reversalOf   uuid.UUID
		originalTier string
	)
	if body.ReversalOfRef != "" {
		reversalOf, err = uuid.Parse(body.ReversalOfRef)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "reversal_of_ref is not a valid id")
			return
		}
		orig, err := aggregate.LoadActionCurrent(r.Context(), b.cfg.Handler.DB(), reversalOf)
		if err != nil {
			writeJSONError(w, http.StatusUnprocessableEntity, "reversal_of_ref: original action not found")
			return
		}
		if orig.Status != aggregate.ActionStatusSucceeded {
			writeJSONError(w, http.StatusUnprocessableEntity,
				"reversal_of_ref: original action is "+orig.Status+", only a SUCCEEDED action can be reversed")
			return
		}
		origDesc, ok := b.cfg.ActionCatalog.Descriptor(orig.ActionType)
		if !ok || origDesc.ReversibleBy == "" {
			writeJSONError(w, http.StatusUnprocessableEntity,
				"reversal_of_ref: action type "+orig.ActionType+" is irreversible")
			return
		}
		if origDesc.ReversibleBy != body.ActionType {
			writeJSONError(w, http.StatusUnprocessableEntity,
				"reversal of "+orig.ActionType+" must use action_type "+origDesc.ReversibleBy)
			return
		}
		originalTier = orig.Tier
	}

	// Build the x-action command (validates against the catalog, applies the
	// blast-radius escalator).
	cmd, err := action.BuildRequestCommand(b.cfg.ActionCatalog, action.ActionRequest{
		ActionType:       body.ActionType,
		Targets:          body.Targets,
		Parameters:       body.Parameters,
		EvidenceRefs:     body.EvidenceRefs,
		Rationale:        body.Rationale,
		InvestigationRef: investigationID,
		ReversalOfRef:    reversalOf,
	}, now)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 04 §7: reversing is the same tier as the original, NOT lower — enforce
	// tier parity before Gate 2 evaluates, so policies see the true tier.
	if originalTier != "" {
		cmd.Tier = action.MaxTier(cmd.Tier, originalTier)
	}

	// Gate 2: evaluate policies over the (post-escalator) request.
	decision, err := b.cfg.Gate2.Evaluate(action.EvalInputForCommand(cmd, actor.Kind, claims.Subject, now))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "policy evaluation: "+err.Error())
		return
	}
	cmd = action.ApplyDecision(cmd, decision)

	// Record the request + its policy evaluation in one transaction.
	env := newEnvelope(investigationID, actor, now)
	res, err := b.cfg.Handler.Handle(r.Context(), env, cmd)
	if err != nil {
		writeCommandError(w, "request action", err)
		return
	}
	b.publishDeltas(res)

	resp := RequestActionResponse{
		ActionID:         cmd.ActionID.String(),
		Tier:             cmd.Tier,
		Mode:             decision.Mode,
		MatchedPolicyRef: decision.MatchedPolicyRef,
		Status:           "PENDING_MANUAL",
	}
	switch decision.Mode {
	case action.ModeAutoPolicy:
		resp.Status, resp.WorkflowID = b.autoApproveAndDispatch(r.Context(), env, cmd, decision, now)
	case action.ModeTwoParty:
		// SEAM OBLIGATION (Phase D approve endpoint): Gate 2's REQUIRE_TWO_PARTY
		// demand lives in the policy_evaluated event and this response — the
		// future approval surface MUST honor it (mode TWO_PARTY, secondary from
		// decision.SecondaryApproverPool), not accept a MANUAL solo approval.
		// Re-derive from the action's policy_evaluated event or re-evaluate
		// Gate 2 at approval time.
		resp.Status = "PENDING_TWO_PARTY"
	}

	writeJSON(w, http.StatusCreated, resp)
}

// autoApproveAndDispatch records the AUTO_POLICY approval (attributed to the
// policy's accountable human, 04 §3.3) and triggers the ActionLifecycle
// workflow. Returns the resulting status + workflow id. A missing accountable or
// a trigger failure degrades to PENDING_MANUAL rather than dropping the action.
func (b *Backend) autoApproveAndDispatch(ctx context.Context, reqEnv aggregate.Envelope, cmd aggregate.RequestAction, decision action.Decision, now time.Time) (status, workflowID string) {
	if decision.PolicyAccountable == "" {
		log.Printf("action %s: AUTO_POLICY matched %s but no accountable human; leaving for manual approval",
			cmd.ActionID, decision.MatchedPolicyRef)
		return "PENDING_MANUAL", ""
	}

	// The approval is attributed to the policy's accountable human, who is
	// the recorded principal — satisfying the actor/approver invariant.
	approveEnv := newEnvelope(reqEnv.AggregateID,
		aggregate.Actor{PrincipalID: decision.PolicyAccountable, Kind: aggregate.ActorHuman}, now)
	approveRes, err := b.cfg.Handler.Handle(ctx, approveEnv, aggregate.ApproveAction{
		ActionID: cmd.ActionID,
		Authorization: aggregate.Authorization{
			Mode:               aggregate.AuthModeAutoPolicy,
			Stage:              aggregate.AuthStageSolo,
			PrimaryApproverRef: decision.PolicyAccountable,
			PrimaryApprovedAt:  now,
			PolicyRef:          decision.MatchedPolicyRef,
		},
	})
	if err != nil {
		log.Printf("action %s: auto-approve failed: %v", cmd.ActionID, err)
		return "PENDING_MANUAL", ""
	}
	b.publishDeltas(approveRes)

	// Trigger the durable dispatch workflow (C.4). If the client isn't wired or
	// the trigger fails, the action is APPROVED and durable in the event log —
	// a supervisor sweep or manual retrigger can pick it up.
	wfID := b.startActionWorkflow(ctx, dispatchSpec{
		ActionID:      cmd.ActionID,
		AggregateID:   reqEnv.AggregateID,
		TenantID:      reqEnv.TenantID,
		ApproverID:    decision.PolicyAccountable,
		ActionType:    cmd.ActionType,
		Targets:       cmd.Targets,
		Parameters:    cmd.Parameters,
		ReversalOfRef: cmd.ReversalOfRef,
	})
	return "APPROVED", wfID
}

// dispatchSpec is the frozen action content needed to start the durable
// dispatch workflow — shared by the auto-approval path and the manual approval
// endpoint so both trigger dispatch identically.
type dispatchSpec struct {
	ActionID      uuid.UUID
	AggregateID   uuid.UUID
	TenantID      uuid.UUID
	ApproverID    string
	ActionType    string
	Targets       []aggregate.TargetSpec
	Parameters    json.RawMessage
	ReversalOfRef uuid.UUID
}

// startActionWorkflow triggers the ActionLifecycle (or ReversalSaga for a
// reversal, 04 §7) for a now-APPROVED action. Returns the workflow id, or ""
// when the dispatch client is not wired or the trigger fails — in which case the
// action is APPROVED and durable in the event log for a later retrigger.
func (b *Backend) startActionWorkflow(ctx context.Context, s dispatchSpec) string {
	client := b.getDispatchClient()
	if client == nil {
		return ""
	}
	lifecycle := temporal.ActionLifecycleInput{
		ActionID:    s.ActionID.String(),
		AggregateID: s.AggregateID.String(),
		TenantID:    s.TenantID.String(),
		ApproverID:  s.ApproverID,
		ActionType:  s.ActionType,
		Targets:     s.Targets,
		Parameters:  paramsMap(s.Parameters),
	}
	var (
		wfID string
		err  error
	)
	if s.ReversalOfRef != uuid.Nil {
		// 04 §7.1 Position C: the REVERSED status claim on the original is gated
		// on its reversibility classification — only a RELIABLE original may be
		// marked REVERSED on a successful undo; a best_effort original (e.g.
		// ioc.block) gets action.reversal_attempted instead and stays SUCCEEDED.
		// The classification is read from the value FROZEN on the original at
		// request time (so a catalog edit cannot re-classify it in flight),
		// falling back to the live catalog for actions requested before the
		// field existed. A lookup failure defaults to NOT reliable — the
		// conservative, honest choice.
		reliable := false
		if orig, lerr := aggregate.LoadActionCurrent(ctx, b.cfg.Handler.DB(), s.ReversalOfRef); lerr != nil {
			log.Printf("action %s: reversal reliability lookup for original %s failed (defaulting to best-effort): %v",
				s.ActionID, s.ReversalOfRef, lerr)
		} else if orig.Reversibility != "" {
			reliable = orig.Reversibility == action.ReversibilityReversible
		} else if d, ok := b.cfg.ActionCatalog.Descriptor(orig.ActionType); ok {
			reliable = d.ReliablyReversible()
		}
		wfID, err = client.StartReversalSaga(ctx, temporal.ReversalSagaInput{
			OriginalActionID: s.ReversalOfRef.String(),
			Reversing:        lifecycle,
			OriginalReliable: reliable,
		})
	} else {
		wfID, err = client.StartActionLifecycle(ctx, lifecycle)
	}
	if err != nil {
		log.Printf("action %s: approved but workflow trigger failed: %v", s.ActionID, err)
		return ""
	}
	return wfID
}

// paramsMap decodes frozen action parameters (JSON object by contract) into the
// map the workflow input carries. A malformed/absent value yields nil.
func paramsMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}
