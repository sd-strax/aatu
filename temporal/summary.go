package temporal

import (
	"time"

	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// SummarizeForKnowledgeIndex extracts a concluded investigation's summary and
// writes it to the DERIVED case-summaries corpus (design/06 §3.2, K3). The
// whole load→extract→embed→write is one activity — the summary bytes never
// enter workflow state, and the extraction is a pure function of the immutable
// concluded investigation, so a retry re-produces (and idempotently revises)
// the same entry. Returns nil when no summary writer is wired (embeddings /
// knowledge off): the workflow degrades to a no-op rather than failing a
// conclusion.
func SummarizeForKnowledgeIndex(ctx workflow.Context, in SummarizeInput) (SummarizeOutput, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy:         &sdktemporal.RetryPolicy{MaximumAttempts: 5},
	})
	var a *SummaryActivities
	var out SummarizeOutput
	if err := workflow.ExecuteActivity(ctx, a.Summarize, in).Get(ctx, &out); err != nil {
		return SummarizeOutput{}, err
	}
	return out, nil
}
