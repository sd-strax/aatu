// Package supervisor manages the lifecycle of reckon's bundled-deps stack:
// Postgres, Temporal, Keycloak, and the in-process backend. A Supervisor
// holds a list of Components and starts them in declaration order, stops
// them in reverse order, and rolls up health checks across all of them.
//
// Cascading restart rules are configured per Component via RestartPolicy.
// Run starts a per-component watcher goroutine that polls health and applies
// the policy: restart with a budgeted sliding window (RestartOnExit) or
// terminate the supervisor (FatalOnExit).
//
// See design/05-component-architecture.md §3.1 for the runtime topology
// this implements, and implementation/phase-a-backbone.md §A.2 for the
// done-bar.
package supervisor
