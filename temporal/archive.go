package temporal

import (
	"time"

	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ArchiveInvestigationInput is the frozen identity of the investigation to
// bundle plus the tenant context the archive path + manifest need.
type ArchiveInvestigationInput struct {
	GroupingID        string `json:"grouping_id"`
	TenantID          string `json:"tenant_id"`
	TenantNamespace   string `json:"tenant_namespace"`
	IncludeSideStores bool   `json:"include_side_stores"`
}

// ArchiveResult is the small descriptor the bundle write returns — the bytes
// stay on disk at Path.
type ArchiveResult struct {
	Path        string `json:"path"`
	Filename    string `json:"filename"`
	ContentHash string `json:"content_hash"`
	SizeBytes   int    `json:"size_bytes"`
}

// ArchiveInvestigation builds a concluded investigation's signed export bundle
// and writes it to the archive target (07 §2.3). The whole load→build→sign→
// write is one activity — the bundle bytes never enter workflow state (they can
// exceed Temporal's payload limit). The workflow provides the durability +
// retry budget around it; the bundle is a pure function of the immutable
// concluded investigation, so a retry re-produces the same content.
func ArchiveInvestigation(ctx workflow.Context, in ArchiveInvestigationInput) (ArchiveResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy:         &sdktemporal.RetryPolicy{MaximumAttempts: 5},
	})
	var a *ArchiveActivities
	var out ArchiveBundleOutput
	if err := workflow.ExecuteActivity(ctx, a.ArchiveBundle, ArchiveBundleInput(in)).Get(ctx, &out); err != nil {
		return ArchiveResult{}, err
	}
	return ArchiveResult(out), nil
}

// PostConclusionResult reports what the pipeline produced. v0 has only the
// export bundle; v1 adds IOC/candidate-SOP/linkage outputs (07 §10).
type PostConclusionResult struct {
	Archive ArchiveResult `json:"archive"`
}

// PostConclusionPipeline is the post-conclusion orchestrator (07 §1.2),
// triggered at InvestigationConcluded. Its v0 scope is export bundle generation
// only (07 §10) — IOC extraction needs real telemetry and candidate SOPs need
// LLM-assisted analysis, both v1. It runs ArchiveInvestigation as a child
// workflow (deterministic id per grouping) so v1 can slot the additional steps
// alongside without restructuring.
func PostConclusionPipeline(ctx workflow.Context, in ArchiveInvestigationInput) (PostConclusionResult, error) {
	childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
		WorkflowID: "archive-" + in.GroupingID,
	})
	var res ArchiveResult
	if err := workflow.ExecuteChildWorkflow(childCtx, ArchiveInvestigation, in).Get(ctx, &res); err != nil {
		return PostConclusionResult{}, err
	}
	return PostConclusionResult{Archive: res}, nil
}
