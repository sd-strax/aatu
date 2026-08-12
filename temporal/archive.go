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

// PostConclusionResult reports what the pipeline produced. v0 has the export
// bundle (step 1) and the knowledge summary (step 2, K3); v1 adds IOC/candidate-
// SOP/linkage outputs (07 §10). SummaryErr is non-nil when step 2 was skipped
// or failed — a summary is best-effort and never fails the conclusion.
type PostConclusionResult struct {
	Archive ArchiveResult   `json:"archive"`
	Summary SummarizeOutput `json:"summary"`
	// SummaryErr carries a step-2 failure as text (the workflow result must be
	// serializable; a real error would fail the whole pipeline).
	SummaryErr string `json:"summary_err,omitempty"`
}

// PostConclusionPipeline is the post-conclusion orchestrator (07 §1.2, §9.1),
// triggered at InvestigationConcluded. v0 steps: (1) export bundle generation
// and (2) knowledge-index summarization (K3). Later steps (IOC extraction,
// candidate SOPs, linkage) slot in alongside. Per 07 §9.1 a failed step does
// not block the others: step 1 (the signed artifact) is load-bearing and its
// failure fails the pipeline, but step 2 is best-effort — a summary that can't
// be produced (knowledge off, transient write error after retries) is recorded
// on the result, never a reason to fail a conclusion.
func PostConclusionPipeline(ctx workflow.Context, in ArchiveInvestigationInput) (PostConclusionResult, error) {
	childCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
		WorkflowID: "archive-" + in.GroupingID,
	})
	var res ArchiveResult
	if err := workflow.ExecuteChildWorkflow(childCtx, ArchiveInvestigation, in).Get(ctx, &res); err != nil {
		return PostConclusionResult{}, err
	}

	out := PostConclusionResult{Archive: res}
	summaryCtx := workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{
		WorkflowID: "summary-" + in.GroupingID,
	})
	summaryIn := SummarizeInput{GroupingID: in.GroupingID, TenantID: in.TenantID}
	if err := workflow.ExecuteChildWorkflow(summaryCtx, SummarizeForKnowledgeIndex, summaryIn).Get(ctx, &out.Summary); err != nil {
		// Best-effort: record the failure, keep the conclusion successful.
		workflow.GetLogger(ctx).Warn("post-conclusion summary failed (non-fatal)", "grouping", in.GroupingID, "err", err)
		out.SummaryErr = err.Error()
	}
	return out, nil
}
