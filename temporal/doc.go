// Package temporal holds Temporal worker registration and the OSS workflow
// inventory: ActionLifecycle, ReversalSaga, RenormalizePass, ArchiveInvestigation,
// PostConclusionPipeline, SummarizeForKnowledgeIndex, and (v1+) the top-level
// InvestigationLifecycleWorkflow. Lands in Phase A.7 (worker registration)
// and Phase C+ (workflow bodies). See design/05-component-architecture.md §3.3.
package temporal
