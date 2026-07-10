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
	"github.com/sd-strax/reckon/module"
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

	// Actor.Kind comes from the JWT delegate_kind claim — NEVER the request body
	// (04 §5.6 seam obligation): otherwise the AI write-protection is spoofable.
	actorKind := aggregate.ActorHuman
	var delegate *aggregate.AIDelegate
	if claims.DelegateKind != "" {
		actorKind = aggregate.ActorAIDelegated
		delegate = &aggregate.AIDelegate{Vendor: claims.DelegateKind}
	}

	now := time.Now().UTC().Truncate(time.Microsecond)

	// Build the x-action command (validates against the catalog, applies the
	// blast-radius escalator).
	cmd, err := action.BuildRequestCommand(b.cfg.ActionCatalog, action.ActionRequest{
		ActionType:       body.ActionType,
		Targets:          body.Targets,
		Parameters:       body.Parameters,
		EvidenceRefs:     body.EvidenceRefs,
		Rationale:        body.Rationale,
		InvestigationRef: investigationID,
	}, now)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Gate 2: evaluate policies over the (post-escalator) request.
	decision, err := b.cfg.Gate2.Evaluate(action.EvalInputForCommand(cmd, actorKind, claims.Subject, now))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "policy evaluation: "+err.Error())
		return
	}
	cmd = action.ApplyDecision(cmd, decision)

	// Record the request + its policy evaluation in one transaction.
	env := aggregate.Envelope{
		AggregateID:   investigationID,
		TenantID:      module.SingleTenantUUID,
		CorrelationID: uuid.New(),
		Actor:         aggregate.Actor{PrincipalID: claims.Subject, Kind: actorKind, Delegate: delegate},
		OccurredAt:    now,
	}
	res, err := b.cfg.Handler.Handle(r.Context(), env, cmd)
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "request action: "+err.Error())
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
		resp.Status = "PENDING_TWO_PARTY"
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
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

	approveEnv := aggregate.Envelope{
		AggregateID:   reqEnv.AggregateID,
		TenantID:      reqEnv.TenantID,
		CorrelationID: uuid.New(),
		// The approval is attributed to the policy's accountable human, who is
		// the recorded principal — satisfying the actor/approver invariant.
		Actor:      aggregate.Actor{PrincipalID: decision.PolicyAccountable, Kind: aggregate.ActorHuman},
		OccurredAt: now,
	}
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
	client := b.getActionClient()
	if client == nil {
		return "APPROVED", ""
	}
	wfID, err := client.StartActionLifecycle(ctx, temporal.ActionLifecycleInput{
		ActionID:    cmd.ActionID.String(),
		AggregateID: reqEnv.AggregateID.String(),
		TenantID:    reqEnv.TenantID.String(),
		ApproverID:  decision.PolicyAccountable,
		ActionType:  cmd.ActionType,
		Targets:     cmd.Targets,
	})
	if err != nil {
		log.Printf("action %s: approved but ActionLifecycle trigger failed: %v", cmd.ActionID, err)
		return "APPROVED", ""
	}
	return "APPROVED", wfID
}
