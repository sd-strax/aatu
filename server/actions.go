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
	// ReversalOfRef, when set, makes this request a reversal of that original
	// action (04 §7): action_type should be the inverse, and auto-approval
	// triggers the ReversalSaga instead of a plain dispatch.
	ReversalOfRef string `json:"reversal_of_ref,omitempty"`
	// RetryOf records lineage to the prior FAILED/EXPIRED action this request
	// replaces (design/ui binding §2.3).
	RetryOf string `json:"retry_of,omitempty"`
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
	// Parameters are the request's frozen parameters — the pre-send preview
	// for notify.* actions renders the message body from here (binding §4:
	// the preview IS the approval surface, so the approver must see exactly
	// what will be sent).
	Parameters json.RawMessage `json:"parameters,omitempty"`

	// Reversibility is the classification frozen at request time (04 §7):
	// REVERSIBLE | BEST_EFFORT | IRREVERSIBLE — the decision-grade card states
	// it honestly BEFORE approval (design/ui 03 §3.3).
	Reversibility string `json:"reversibility,omitempty"`
	// TierEscalated: the blast-radius escalator raised this above the type's
	// default tier (04 §1) — the card says why it is T3.
	TierEscalated bool `json:"tier_escalated,omitempty"`
	// RetryOf: lineage to the action this one replaces (zero when not a retry).
	RetryOf string `json:"retry_of,omitempty"`
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
			ActionID:      a.ActionID.String(),
			ActionType:    a.ActionType,
			Tier:          a.Tier,
			Status:        a.Status,
			RequiredMode:  a.RequiredMode,
			Mode:          a.Mode,
			IsReversal:    a.IsReversal,
			Targets:       a.Targets,
			EvidenceRefs:  a.EvidenceRefs,
			Reversibility: a.Reversibility,
			Parameters:    a.Parameters,
		}
		if a.RetryOf != (uuid.UUID{}) {
			v.RetryOf = a.RetryOf.String()
		}
		if !a.ExpiresAt.IsZero() {
			t := a.ExpiresAt
			v.ExpiresAt = &t
		}
		// The escalation is derivable, not stored: the catalog's default tier
		// for the type vs the frozen tier on the action.
		if b.cfg.ActionCatalog != nil {
			if d, ok := b.cfg.ActionCatalog.Descriptor(a.ActionType); ok && d.DefaultTier != a.Tier && a.Tier == aggregate.TierT3 {
				v.TierEscalated = true
			}
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
	b.dispatchActionRequest(w, r, actorFromClaims(claims), claims.Subject, body)
}

// dispatchActionRequest is the shared request path (fresh request_action and
// re-request of an expired action both flow through it): build the x-action,
// run Gate 2, record, and on auto-approval dispatch. body carries the frozen
// request fields; the caller has already resolved the actor.
func (b *Backend) dispatchActionRequest(w http.ResponseWriter, r *http.Request, actor aggregate.Actor, subject string, body RequestActionBody) {
	investigationID, err := uuid.Parse(body.InvestigationRef)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "investigation_ref is not a valid id")
		return
	}

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
	var retryOf uuid.UUID
	if body.RetryOf != "" {
		if retryOf, err = uuid.Parse(body.RetryOf); err != nil {
			writeJSONError(w, http.StatusBadRequest, "retry_of is not a valid id")
			return
		}
	}
	cmd, err := action.BuildRequestCommand(b.cfg.ActionCatalog, action.ActionRequest{
		ActionType:       body.ActionType,
		Targets:          body.Targets,
		Parameters:       body.Parameters,
		EvidenceRefs:     body.EvidenceRefs,
		Rationale:        body.Rationale,
		InvestigationRef: investigationID,
		ReversalOfRef:    reversalOf,
		RetryOf:          retryOf,
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
	decision, err := b.cfg.Gate2.Evaluate(action.EvalInputForCommand(cmd, actor.Kind, subject, now))
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
	// Invisible activate at the action boundary (01 §Extension 2): the first
	// action of a DRAFT investigation always gets a human — that approval is the
	// activation moment (applyApproveAction transitions draft→active) — so
	// auto-approve is suppressed until the investigation is active. The policy
	// still evaluated and was recorded (would-have-fired); it just doesn't drive
	// this first decision.
	draft := false
	if ic, ierr := aggregate.LoadInvestigationCurrent(r.Context(), b.cfg.Handler.DB(), investigationID); ierr == nil {
		draft = ic.Status == aggregate.StatusDraft
	}
	switch decision.Mode {
	case action.ModeAutoPolicy:
		if draft {
			resp.Status = "PENDING_MANUAL" // held for the activating human approval
		} else {
			resp.Status, resp.WorkflowID = b.autoApproveAndDispatch(r.Context(), env, cmd, decision, now)
		}
	case action.ModeTwoParty:
		// SEAM OBLIGATION (Phase D approve endpoint): Gate 2's REQUIRE_TWO_PARTY
		// demand lives in the policy_evaluated event and this response — the
		// future approval surface MUST honor it (mode TWO_PARTY, secondary from
		// decision.SecondaryApproverPool), not accept a MANUAL solo approval.
		// Re-derive from the action's policy_evaluated event or re-evaluate
		// Gate 2 at approval time.
		resp.Status = "PENDING_TWO_PARTY"
	}

	// A pending action gets its durable expiry timer (02 §3: ActionExpired is
	// system-emitted on expires_at). Best-effort: the deadline stays the
	// invariant (the approve path refuses past it regardless), so a missed
	// start only delays the stored-status transition — the startup sweep
	// backstops it.
	if resp.Status == "PENDING_MANUAL" || resp.Status == "PENDING_TWO_PARTY" {
		b.startExpiryTimer(r.Context(), cmd.ActionID, env.AggregateID, env.TenantID, cmd.ExpiresAt)
	}

	writeJSON(w, http.StatusCreated, resp)
}

// startExpiryTimer starts the durable expiry timer for one pending action.
// Best-effort and idempotent (the workflow id derives from the action id).
func (b *Backend) startExpiryTimer(ctx context.Context, actionID, aggregateID, tenantID uuid.UUID, expiresAt time.Time) {
	if expiresAt.IsZero() {
		return
	}
	client := b.getDispatchClient()
	if client == nil {
		return
	}
	if err := client.StartActionExpiryTimer(ctx, temporal.ActionExpiryTimerInput{
		ActionID:    actionID.String(),
		AggregateID: aggregateID.String(),
		TenantID:    tenantID.String(),
		ExpiresAt:   expiresAt,
	}); err != nil {
		log.Printf("action %s: could not start expiry timer (the deadline still binds at approve; the startup sweep will retry): %v", actionID, err)
	}
}

// sweepExpiryTimers ensures every pending action has its durable expiry timer —
// the startup reconciliation covering actions requested before the timer
// existed, or whose start was missed. Idempotent (per-action workflow ids);
// already-elapsed deadlines fire immediately, converging stored statuses that
// lazy expiry left behind.
func (b *Backend) sweepExpiryTimers(ctx context.Context) {
	pending, err := aggregate.ListPendingActionCurrents(ctx, b.cfg.Handler.DB())
	if err != nil {
		log.Printf("expiry sweep: list pending actions: %v", err)
		return
	}
	started := 0
	for _, a := range pending {
		if a.ExpiresAt.IsZero() {
			continue
		}
		b.startExpiryTimer(ctx, a.ActionID, a.AggregateID, module.SingleTenantUUID, a.ExpiresAt)
		started++
	}
	if started > 0 {
		log.Printf("expiry sweep: ensured timers for %d pending action(s)", started)
	}
}

// RerequestBody is the POST /api/actions/{id}/rerequest request — the
// analyst's re-affirmation note (why the action is still warranted).
type RerequestBody struct {
	Rationale string `json:"rationale"`
}

// rerequestAction re-requests an EXPIRED action (design/ui: the re-request
// affordance). Re-request is NOT a bypass of expiry — it creates a NEW action
// (the dispatch ledger forbids re-using an id, 08 §6b) with the ORIGINAL's
// frozen fields (same descriptor, targets, parameters, evidence), fresh Gate 2,
// a fresh approval window, and retry_of lineage — which the analyst must then
// separately approve. Expiry's freshness guarantee is honored: re-requesting is
// the conscious re-affirmation it exists to elicit, and the new rationale is
// the analyst's statement of why it still holds. Analyst role; the human is the
// requester (a re-request is a human act even if the original was AI-proposed).
func (b *Backend) rerequestAction(w http.ResponseWriter, r *http.Request, priorID uuid.UUID) {
	if b.cfg.Handler == nil || b.cfg.Gate2 == nil || b.cfg.ActionCatalog == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "action layer not configured")
		return
	}
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth context missing")
		return
	}
	prior, err := aggregate.LoadActionCurrent(r.Context(), b.cfg.Handler.DB(), priorID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "action not found")
		return
	}
	now := commandNow()

	// Only a spent-but-unexecuted action is re-requestable: EXPIRED or REJECTED
	// by stored status, or a pending action whose frozen deadline has elapsed.
	// The deadline is the INVARIANT (the approve path refuses past it
	// regardless); the stored EXPIRED status is scheduling, owned by the
	// durable expiry timer — which may lag by moments, so the gate checks the
	// invariant directly rather than waiting on the schedule. No status
	// transition happens here: the timer owns that, and it fires on its own.
	deadlineElapsed := (prior.Status == aggregate.ActionStatusRequested ||
		prior.Status == aggregate.ActionStatusPendingSecondary) &&
		!prior.ExpiresAt.IsZero() && prior.ExpiresAt.Before(now)
	switch {
	case prior.Status == aggregate.ActionStatusExpired,
		prior.Status == aggregate.ActionStatusRejected,
		deadlineElapsed:
		// re-requestable
	default:
		writeJSONError(w, http.StatusUnprocessableEntity,
			"only an EXPIRED or REJECTED action can be re-requested; this one is "+prior.Status+" and its approval window has not elapsed")
		return
	}

	var body RerequestBody
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	rationale := body.Rationale
	if rationale == "" {
		rationale = "Re-requested after expiry — re-affirmed as still warranted."
	}

	// Reconstruct the request from the original's FROZEN fields — a faithful
	// "same action, fresh clock", not a client reconstruction that could drift.
	b.dispatchActionRequest(w, r,
		aggregate.Actor{PrincipalID: claims.Subject, Kind: aggregate.ActorHuman}, claims.Subject,
		RequestActionBody{
			ActionType:       prior.ActionType,
			Targets:          prior.Targets,
			Parameters:       prior.Parameters,
			EvidenceRefs:     prior.EvidenceRefs,
			Rationale:        rationale,
			InvestigationRef: prior.AggregateID.String(),
			RetryOf:          priorID.String(),
		})
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

	// Route the dispatch to the investigation's organization (03 §3.5). The
	// source scope lives on the immutable Seed, so every action in an
	// investigation inherits one value — reading it here covers the auto-approve,
	// manual-approve, and reversal paths uniformly (all flow through this func).
	// A lookup miss leaves it empty: fail-closed for a scoped tenant (a scoped
	// write finds no binding rather than mis-routing) and a no-op for a
	// single-organization one.
	if b.cfg.Handler != nil {
		if inv, err := aggregate.LoadInvestigationCurrent(ctx, b.cfg.Handler.DB(), s.AggregateID); err != nil {
			log.Printf("action %s: source-scope lookup failed, dispatch will be unscoped: %v", s.ActionID, err)
		} else if inv.Seed != nil {
			lifecycle.SourceScope = inv.Seed.SourceScope
		}
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
