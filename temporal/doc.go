// Package temporal holds the in-process Temporal worker and the OSS workflow
// inventory. The worker (worker.go) runs in the same OS process as the backend
// — there is no separate worker binary (design/05-component-architecture.md
// §3.3) — and satisfies supervisor.Component; the dispatch Client (client.go)
// is the command-path entry point for starting workflows.
//
// Phase A.7 (done) registers the worker on the `reckon` task queue with the
// full inventory — ActionLifecycle, ReversalSaga, RenormalizePass,
// ArchiveInvestigation, PostConclusionPipeline, SummarizeForKnowledgeIndex —
// as skeletons that fail fast with a non-retryable "unimplemented" error, plus
// the trivial Ping workflow that proves the round trip. Phase C+ fills the
// skeleton bodies (each with the real input/output its owning spec defines),
// and v1+ adds the top-level InvestigationLifecycleWorkflow.
package temporal
