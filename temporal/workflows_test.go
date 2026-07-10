package temporal

import (
	"errors"
	"testing"

	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

// TestPingWorkflow runs the wireup prover in the in-memory test environment —
// no dev server, no -short gate.
func TestPingWorkflow(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()
	env.ExecuteWorkflow(Ping, "hi")

	if !env.IsWorkflowCompleted() {
		t.Fatal("Ping workflow did not complete")
	}
	if err := env.GetWorkflowError(); err != nil {
		t.Fatalf("Ping errored: %v", err)
	}
	var out string
	if err := env.GetWorkflowResult(&out); err != nil {
		t.Fatalf("get result: %v", err)
	}
	if out != "pong:hi" {
		t.Errorf("Ping result = %q; want %q", out, "pong:hi")
	}
}

// TestSkeletonWorkflowsUnimplemented asserts every domain workflow fails fast
// with a non-retryable Unimplemented ApplicationError until Phase C fills it —
// a premature call must not look like success.
func TestSkeletonWorkflowsUnimplemented(t *testing.T) {
	skeletons := map[string]func(workflow.Context) error{
		WorkflowRenormalizePass:            RenormalizePass,
		WorkflowArchiveInvestigation:       ArchiveInvestigation,
		WorkflowPostConclusionPipeline:     PostConclusionPipeline,
		WorkflowSummarizeForKnowledgeIndex: SummarizeForKnowledgeIndex,
	}
	for name, wf := range skeletons {
		t.Run(name, func(t *testing.T) {
			ts := &testsuite.WorkflowTestSuite{}
			env := ts.NewTestWorkflowEnvironment()
			env.ExecuteWorkflow(wf)

			if !env.IsWorkflowCompleted() {
				t.Fatal("workflow did not complete")
			}
			err := env.GetWorkflowError()
			if err == nil {
				t.Fatal("skeleton returned nil; want an unimplemented error")
			}
			var appErr *sdktemporal.ApplicationError
			if !errors.As(err, &appErr) {
				t.Fatalf("error is %T (%v); want *temporal.ApplicationError", err, err)
			}
			if appErr.Type() != unimplementedErrType {
				t.Errorf("error type = %q; want %q", appErr.Type(), unimplementedErrType)
			}
		})
	}
}
