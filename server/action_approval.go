package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/module"
)

// ApproveActionBody is the optional body of an approve request. ChallengeResponse
// carries the typed-challenge value for higher-tier confirmations (04 §5.5); it
// is recorded on the Authorization for audit.
type ApproveActionBody struct {
	ChallengeResponse string `json:"challenge_response,omitempty"`
}

// RejectActionBody is the body of a reject request.
type RejectActionBody struct {
	Reason string `json:"reason"`
}

// ActionDecisionResponse reports where an approve/reject left the action.
type ActionDecisionResponse struct {
	ActionID   string `json:"action_id"`
	Status     string `json:"status"`
	Stage      string `json:"stage,omitempty"`
	WorkflowID string `json:"workflow_id,omitempty"`
}

// actionsItem routes /api/actions/{id}/{approve|reject}. Both are POST, analyst
// role — approving and rejecting are human acts (the aggregate's AI-write
// protection denies them to an AI delegate; the endpoint refuses one early with
// a clear 403).
func (b *Backend) actionsItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/actions/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		writeJSONError(w, http.StatusNotFound, "not found")
		return
	}
	actionID, err := uuid.Parse(parts[0])
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "action id is not a valid id")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	switch parts[1] {
	case "approve":
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) {
			b.approveAction(w, r, actionID)
		})
	case "reject":
		b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, func(w http.ResponseWriter, r *http.Request) {
			b.rejectAction(w, r, actionID)
		})
	default:
		writeJSONError(w, http.StatusNotFound, "not found")
	}
}

// approveAction handles POST /api/actions/{id}/approve. It honors the frozen
// Gate 2 requirement (the Phase D two-party seam): for a TWO_PARTY action the
// first approval is recorded as PRIMARY (→ PENDING_SECONDARY, no dispatch) and a
// second, distinct approver as SECONDARY (→ APPROVED, dispatch); a MANUAL action
// is a single SOLO approval. The aggregate is the enforcement point — it rejects
// a solo approval on a TWO_PARTY action, a repeated approver, and an out-of-pool
// secondary — so this handler cannot smuggle a weaker approval through.
func (b *Backend) approveAction(w http.ResponseWriter, r *http.Request, actionID uuid.UUID) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "action layer not configured")
		return
	}
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth context missing")
		return
	}
	// Approving is a human act. An AI delegate is denied here (and again at the
	// aggregate boundary via the AI-write-protection allowlist).
	if claims.DelegateKind != "" {
		writeJSONError(w, http.StatusForbidden, "an AI delegate cannot approve an action")
		return
	}

	ac, err := aggregate.LoadActionCurrent(r.Context(), b.cfg.Handler.DB(), actionID)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "action not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "load action: "+err.Error())
		return
	}

	var body ApproveActionBody
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body) // body is optional
	}

	// T3 approval requires the typed challenge (04 §5.5): the panel renders the
	// full challenge UX, but the server floor is that the intent-proving field
	// can never be silently absent from a T3 authorization record.
	if ac.Tier == aggregate.TierT3 && body.ChallengeResponse == "" {
		writeJSONError(w, http.StatusUnprocessableEntity, "a T3 approval requires challenge_response (typed challenge, 04 §5.5)")
		return
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	auth, willApprove, approverID, errMsg := b.buildApproval(ac, claims.Subject, body.ChallengeResponse, now)
	if errMsg != "" {
		writeJSONError(w, http.StatusConflict, errMsg)
		return
	}

	env := aggregate.Envelope{
		AggregateID:   ac.AggregateID,
		TenantID:      module.SingleTenantUUID,
		CorrelationID: uuid.New(),
		// Derived from the claims (not hardcoded HUMAN): the 403 above already
		// rejected delegate tokens, and deriving keeps the aggregate's
		// AI-write-protection a REAL second layer behind that check.
		Actor:      actorFromClaims(claims),
		OccurredAt: now,
	}
	res, err := b.cfg.Handler.Handle(r.Context(), env, aggregate.ApproveAction{ActionID: actionID, Authorization: auth})
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "approve action: "+err.Error())
		return
	}
	b.publishDeltas(res)

	resp := ActionDecisionResponse{ActionID: actionID.String(), Stage: auth.Stage}
	if willApprove {
		resp.Status = aggregate.ActionStatusApproved
		resp.WorkflowID = b.startActionWorkflow(r.Context(), dispatchSpec{
			ActionID:      actionID,
			AggregateID:   ac.AggregateID,
			TenantID:      module.SingleTenantUUID,
			ApproverID:    approverID,
			ActionType:    ac.ActionType,
			Targets:       ac.Targets,
			Parameters:    ac.Parameters,
			ReversalOfRef: ac.ReversalOfRef,
		})
	} else {
		resp.Status = aggregate.ActionStatusPendingSecondary
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// buildApproval derives the Authorization for this approval from the action's
// frozen requirement and current status. It returns the authorization, whether
// the action reaches APPROVED (and should dispatch), the human whose principal
// the dispatch workflow carries, and a non-empty conflict message if the action
// is not in an approvable state. It does NOT enforce the two-party/pool/distinct
// rules — those live at the aggregate boundary (the single write path); this
// only shapes the command the aggregate then validates.
func (b *Backend) buildApproval(ac aggregate.ActionCurrent, approver, challenge string, now time.Time) (auth aggregate.Authorization, willApprove bool, approverID, errMsg string) {
	// expires_at is the approval deadline the requester declared, frozen at
	// request time. No expiry timer runs in v0 (the ExpireAction emitter is a
	// v1 refinement), so the endpoint is the enforcement point: a lapsed
	// request must not be approvable a week later as if the TTL meant nothing.
	if !ac.ExpiresAt.IsZero() && now.After(ac.ExpiresAt) {
		return aggregate.Authorization{}, false, "", "action expired at " + ac.ExpiresAt.UTC().Format(time.RFC3339) + " and can no longer be approved"
	}

	// Two-party branch: selected by the frozen requirement, OR by an action
	// already sitting in PENDING_SECONDARY (a two-party primary recorded without
	// a frozen requirement must still complete as two-party, never fall through
	// to a solo path).
	if ac.RequiredMode == aggregate.AuthModeTwoParty || ac.Status == aggregate.ActionStatusPendingSecondary {
		switch ac.Status {
		case aggregate.ActionStatusRequested:
			// Primary approval: records the first approver, awaits a second.
			return aggregate.Authorization{
				Mode:               aggregate.AuthModeTwoParty,
				Stage:              aggregate.AuthStagePrimary,
				PrimaryApproverRef: approver,
				PrimaryApprovedAt:  now,
				ChallengeResponse:  challenge,
			}, false, approver, ""
		case aggregate.ActionStatusPendingSecondary:
			// Secondary approval: the distinct second approver completes it. The
			// authorization record cites the PRIMARY approval's TRUE time (from
			// the projection) — never the secondary's clock: this final record
			// is the citable authorization for the action, and a fabricated
			// primary timestamp would be an audit lie. The dispatch workflow
			// carries the primary approver (the accountable initiator).
			return aggregate.Authorization{
				Mode:                 aggregate.AuthModeTwoParty,
				Stage:                aggregate.AuthStageSecondary,
				PrimaryApproverRef:   ac.PrimaryApprover,
				PrimaryApprovedAt:    ac.PrimaryApprovedAt,
				SecondaryApproverRef: approver,
				SecondaryApprovedAt:  &now,
				ChallengeResponse:    challenge,
			}, true, ac.PrimaryApprover, ""
		default:
			return aggregate.Authorization{}, false, "", "action " + ac.Status + " is not pending approval"
		}
	}

	// MANUAL (or unset requirement): a single solo approval.
	if ac.Status != aggregate.ActionStatusRequested {
		return aggregate.Authorization{}, false, "", "action " + ac.Status + " is not pending approval"
	}
	return aggregate.Authorization{
		Mode:               aggregate.AuthModeManual,
		Stage:              aggregate.AuthStageSolo,
		PrimaryApproverRef: approver,
		PrimaryApprovedAt:  now,
		ChallengeResponse:  challenge,
	}, true, approver, ""
}

// rejectAction handles POST /api/actions/{id}/reject. Rejecting is a human act;
// an AI delegate is denied.
func (b *Backend) rejectAction(w http.ResponseWriter, r *http.Request, actionID uuid.UUID) {
	if b.cfg.Handler == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "action layer not configured")
		return
	}
	claims, ok := authz.FromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "auth context missing")
		return
	}
	if claims.DelegateKind != "" {
		writeJSONError(w, http.StatusForbidden, "an AI delegate cannot reject an action")
		return
	}

	ac, err := aggregate.LoadActionCurrent(r.Context(), b.cfg.Handler.DB(), actionID)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSONError(w, http.StatusNotFound, "action not found")
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "load action: "+err.Error())
		return
	}

	var body RejectActionBody
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	env := aggregate.Envelope{
		AggregateID:   ac.AggregateID,
		TenantID:      module.SingleTenantUUID,
		CorrelationID: uuid.New(),
		Actor:         actorFromClaims(claims), // derived, so the allowlist backs the 403 above
		OccurredAt:    now,
	}
	res, err := b.cfg.Handler.Handle(r.Context(), env, aggregate.RejectAction{ActionID: actionID, Reason: body.Reason})
	if err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "reject action: "+err.Error())
		return
	}
	b.publishDeltas(res)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ActionDecisionResponse{
		ActionID: actionID.String(),
		Status:   aggregate.ActionStatusRejected,
	})
}
