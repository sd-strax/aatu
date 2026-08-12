package temporal

import (
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// Workflow type names — the stable identifiers registered on the task queue.
// These names are the contract Phase C must preserve when it fills the bodies:
// renaming a Go function must not change the registered name, so registration
// pins each one explicitly (workflow.RegisterOptions.Name).
const (
	WorkflowActionLifecycle            = "ActionLifecycle"
	WorkflowActionExpiryTimer          = "ActionExpiryTimer"
	WorkflowReversalSaga               = "ReversalSaga"
	WorkflowRenormalizePass            = "RenormalizePass"
	WorkflowArchiveInvestigation       = "ArchiveInvestigation"
	WorkflowPostConclusionPipeline     = "PostConclusionPipeline"
	WorkflowSummarizeForKnowledgeIndex = "SummarizeForKnowledgeIndex"

	// WorkflowPing is the A.7 wireup prover — not a domain workflow. It exists
	// so the worker registration round trip is testable with zero Phase C
	// business logic. See Client.Ping.
	WorkflowPing = "Ping"

	// unimplementedErrType is the ApplicationError type the skeleton domain
	// workflows return. Non-retryable: a premature call fails fast and visibly
	// rather than spinning on retries until Phase C fills the body.
	unimplementedErrType = "Unimplemented"
)

// registerWorkflows registers the full OSS workflow inventory (05 §3.3) on the
// worker under stable type names. Called by Worker.Start.
func registerWorkflows(w worker.Worker) {
	w.RegisterWorkflowWithOptions(Ping, workflow.RegisterOptions{Name: WorkflowPing})
	w.RegisterWorkflowWithOptions(ActionLifecycle, workflow.RegisterOptions{Name: WorkflowActionLifecycle})
	w.RegisterWorkflowWithOptions(ActionExpiryTimer, workflow.RegisterOptions{Name: WorkflowActionExpiryTimer})
	w.RegisterWorkflowWithOptions(ReversalSaga, workflow.RegisterOptions{Name: WorkflowReversalSaga})
	w.RegisterWorkflowWithOptions(RenormalizePass, workflow.RegisterOptions{Name: WorkflowRenormalizePass})
	w.RegisterWorkflowWithOptions(ArchiveInvestigation, workflow.RegisterOptions{Name: WorkflowArchiveInvestigation})
	w.RegisterWorkflowWithOptions(PostConclusionPipeline, workflow.RegisterOptions{Name: WorkflowPostConclusionPipeline})
	w.RegisterWorkflowWithOptions(SummarizeForKnowledgeIndex, workflow.RegisterOptions{Name: WorkflowSummarizeForKnowledgeIndex})
}

// Ping echoes its input, prefixed, proving the command → Temporal → worker →
// result round trip. See WorkflowPing.
func Ping(ctx workflow.Context, msg string) (string, error) {
	workflow.GetLogger(ctx).Info("Ping workflow invoked", "msg", msg)
	return "pong:" + msg, nil
}

// unimplemented is the shared body of every skeleton domain workflow: it logs
// and returns a non-retryable ApplicationError. Phase C replaces each call site
// with a real body (and real input/output types) per the workflow's owning
// spec — the signatures here are deliberate placeholders.
func unimplemented(ctx workflow.Context, name string) error {
	workflow.GetLogger(ctx).Warn("skeleton workflow invoked before its Phase C implementation", "workflow", name)
	return sdktemporal.NewApplicationError(name+" is not implemented until Phase C", unimplementedErrType)
}

// The OSS domain workflow inventory (05 §3.3). ActionLifecycle (dispatch) and
// ReversalSaga have their real bodies in action_lifecycle.go / reversal_saga.go
// (C.4); the rest are skeletons whose bodies land in later phases.

// RenormalizePass re-runs normalizers over stored telemetry when a normalizer
// version changes. (Phase C+.)
func RenormalizePass(ctx workflow.Context) error { return unimplemented(ctx, WorkflowRenormalizePass) }

// ArchiveInvestigation and PostConclusionPipeline have their real bodies in
// archive.go (Phase D.5); SummarizeForKnowledgeIndex in summary.go (K3).
