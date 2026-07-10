package action

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/capability"
)

// WriteOutcome is the terminal outcome of a dispatched action (08 §5,
// = Execution.final_outcome).
type WriteOutcome string

const (
	OutcomeSucceeded WriteOutcome = "SUCCEEDED"
	OutcomeFailed    WriteOutcome = "FAILED"
	OutcomePartial   WriteOutcome = "PARTIAL" // some targets OK, some not
	OutcomeTimeout   WriteOutcome = "TIMEOUT"
)

// PerTargetResult is one target's outcome. UNKNOWN is first-class: the call left
// reckon but the adapter cannot confirm the effect — it never coerces to OK
// (08 §5, §6c).
type PerTargetResult string

const (
	TargetOK      PerTargetResult = "OK"
	TargetFail    PerTargetResult = "FAIL"
	TargetUnknown PerTargetResult = "UNKNOWN"
)

// AuditDepth is FULL for DIRECT dispatch, EXTERNAL for SOAR-delegated (the
// orchestrator's internal steps aren't in reckon's log; 08 §7).
type AuditDepth string

const (
	AuditFull     AuditDepth = "FULL"
	AuditExternal AuditDepth = "EXTERNAL"
)

// WriteErrorClass is the executor-facing error taxonomy (08 §5), the write-side
// collapse of the read-side ErrorClass.
type WriteErrorClass string

const (
	WriteRetryable WriteErrorClass = "RETRYABLE_ERROR" // rate limit, transient 5xx, network → retry in budget
	WriteFatal     WriteErrorClass = "FATAL_ERROR"     // auth, malformed, target-not-found → no retry
)

// WriteResult is the write analog of capability.CapabilityResult (08 §5). Its
// fields map onto the Execution record and the ActionResulted payload so the
// contract and the event log agree by construction.
type WriteResult struct {
	FinalOutcome     WriteOutcome               `json:"final_outcome"`
	PerTargetResults map[string]PerTargetResult `json:"per_target_results"`
	AdapterRequestID string                     `json:"adapter_request_id"`
	ErrorClass       WriteErrorClass            `json:"error_class,omitempty"` // "" on success
	ErrorDetail      string                     `json:"error_detail,omitempty"`
	AuditDepth       AuditDepth                 `json:"audit_depth"`
	RawResponseRef   string                     `json:"raw_response_ref,omitempty"`
}

// WriteError wraps a dispatch error with its classification. The resolver/
// workflow branch on Class (retry within budget vs terminal FAILED).
type WriteError struct {
	Class WriteErrorClass
	Err   error
}

func (e *WriteError) Error() string { return fmt.Sprintf("%s: %v", e.Class, e.Err) }
func (e *WriteError) Unwrap() error { return e.Err }

func writeErrorf(class WriteErrorClass, format string, args ...any) *WriteError {
	return &WriteError{Class: class, Err: fmt.Errorf(format, args...)}
}

// WriteAdapter is the write-side contract (08 §5). It extends the read Adapter's
// identity/health with a Dispatch that takes a mandatory idempotency key and
// returns a WriteResult (an outcome, not an observation — there is no normalizer
// on the write path). An adapter may serve reads, writes, or both.
type WriteAdapter interface {
	Name() string
	Class() capability.AdapterClass
	SupportedActionOps() []string
	Dispatch(ctx context.Context, operation string, params map[string]any, idempotencyKey string) (WriteResult, error)
	Health() capability.HealthStatus
}

// idempotencyNamespace scopes the deterministic idempotency keys (08 §6a).
var idempotencyNamespace = uuid.MustParse("a1d90000-0000-4000-8000-000000000001")

// IdempotencyKey derives the stable, deterministic key for one action against
// one target (08 §6a): the same logical action against the same target always
// presents the same key, so a re-issue after an ambiguous failure dedups
// downstream. An empty target yields the action-level key used when a single
// Dispatch covers all targets.
func IdempotencyKey(actionID uuid.UUID, target string) string {
	sum := sha256.Sum256([]byte(actionID.String() + "|" + target))
	return uuid.NewSHA1(idempotencyNamespace, sum[:]).String()
}
