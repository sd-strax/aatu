package temporal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
)

// TestArchiveInvestigation_RunsBundleActivity: the workflow delegates to the
// single ArchiveBundle activity and returns its descriptor unchanged.
func TestArchiveInvestigation_RunsBundleActivity(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()
	var a *ArchiveActivities

	env.OnActivity(a.ArchiveBundle, mock.Anything, mock.MatchedBy(func(in ArchiveBundleInput) bool {
		return in.GroupingID == "g-1" && in.IncludeSideStores
	})).Return(ArchiveBundleOutput{
		Path: "/archive/ns/investigation-g-1.tar.gz", Filename: "investigation-g-1.tar.gz",
		ContentHash: "deadbeef", SizeBytes: 2048,
	}, nil)

	env.ExecuteWorkflow(ArchiveInvestigation, ArchiveInvestigationInput{
		GroupingID: "g-1", TenantID: "t-1", TenantNamespace: "ns", IncludeSideStores: true,
	})

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow not clean: %v", env.GetWorkflowError())
	}
	var res ArchiveResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatal(err)
	}
	if res.ContentHash != "deadbeef" || res.SizeBytes != 2048 {
		t.Errorf("result = %+v; want the activity's descriptor", res)
	}
}

// TestArchiveBundle_RejectsTraversalNamespace: TenantNamespace becomes a path
// component under the archive root — anything that is not a well-formed UUID
// (e.g. "../../tmp/evil") is rejected before any filesystem or DB touch.
func TestArchiveBundle_RejectsTraversalNamespace(t *testing.T) {
	acts := NewArchiveActivities(nil, nil, t.TempDir())
	_, err := acts.ArchiveBundle(context.Background(), ArchiveBundleInput{
		GroupingID:      "11111111-1111-1111-1111-111111111111",
		TenantID:        "22222222-2222-2222-2222-222222222222",
		TenantNamespace: "../../../../tmp/evil",
	})
	if err == nil {
		t.Fatal("traversal namespace accepted as an archive path component")
	}
}

// TestPostConclusionPipeline_RunsArchive: the v0 pipeline's single step is the
// export bundle — it runs ArchiveInvestigation as a child and surfaces its
// result. (IOC/SOP steps are v1, 07 §10.)
func TestPostConclusionPipeline_RunsArchive(t *testing.T) {
	ts := &testsuite.WorkflowTestSuite{}
	env := ts.NewTestWorkflowEnvironment()

	env.OnWorkflow(ArchiveInvestigation, mock.Anything, mock.Anything).Return(ArchiveResult{
		Path: "/archive/ns/x.tar.gz", Filename: "x.tar.gz", ContentHash: "cafe", SizeBytes: 512,
	}, nil)

	env.ExecuteWorkflow(PostConclusionPipeline, ArchiveInvestigationInput{
		GroupingID: "g-2", TenantID: "t-1", TenantNamespace: "ns",
	})

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow not clean: %v", env.GetWorkflowError())
	}
	var res PostConclusionResult
	if err := env.GetWorkflowResult(&res); err != nil {
		t.Fatal(err)
	}
	if res.Archive.ContentHash != "cafe" {
		t.Errorf("pipeline result = %+v; want the archive child's result", res)
	}
}
