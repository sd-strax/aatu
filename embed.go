// Package reckon holds the demo content `reckon init` materializes into a fresh
// install so the bundled lateral-movement scenario runs out of the box, without
// a repo checkout. The embedded files are the very same fixtures/ and examples/
// the capability + action smoke tests load from disk — one source of truth,
// embedded here for the binary and read directly there by the tests.
package reckon

import "embed"

// DemoFS carries the demo fixture scenario (OCSF events + declared write
// results), the example tenant capability/action configs, and the demo
// knowledge pack (SOPs + prior-case summaries under demo/knowledge). `reckon
// demo seed` materializes the fixtures/configs into the install's config
// directory (see runtime.SeedDemo) and loads the knowledge pack into the
// knowledge corpus (server seeds it). Kept in the module root so the //go:embed
// patterns can reach these trees (embed cannot traverse `..`).
//
//go:embed fixtures examples demo
var DemoFS embed.FS

// DemoKnowledgeSOPs / DemoKnowledgeCases are the embedded knowledge-pack
// subtrees the demo seed loads: institutional SOPs (markdown + frontmatter) and
// prior concluded-case summaries (JSON), both scoped to the DemoScenario world
// so similar-case recall and SOP consultation have real material to surface.
const (
	DemoKnowledgeSOPs  = "demo/knowledge/sops"
	DemoKnowledgeCases = "demo/knowledge/cases"
)

// DemoScenario is the fixture scenario `reckon init` seeds and wires the demo
// capability + action config to (03 §9, 08 §9). It names the fixture
// subdirectory under fixtures/.
const DemoScenario = "lateral-movement-via-rdp"

// DemoConfigBase is the base filename (no extension) of the example capability
// and action configs under examples/{capability,action}/. It differs from
// DemoScenario: the configs are named for the workflow, the fixtures for the
// full scenario id.
const DemoConfigBase = "lateral-movement"
