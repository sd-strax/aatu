// Package reckon holds the demo content `reckon init` materializes into a fresh
// install so the bundled lateral-movement scenario runs out of the box, without
// a repo checkout. The embedded files are the very same fixtures/ and examples/
// the capability + action smoke tests load from disk — one source of truth,
// embedded here for the binary and read directly there by the tests.
package reckon

import "embed"

// DemoFS carries the demo fixture scenario (OCSF events + declared write
// results) and the example tenant capability/action configs. `reckon init`
// copies these into the install's config directory and points the config at
// them (see runtime.Init). Kept in the module root so the //go:embed patterns
// can reach fixtures/ and examples/ (embed cannot traverse `..`).
//
//go:embed fixtures examples
var DemoFS embed.FS

// DemoScenario is the fixture scenario `reckon init` seeds and wires the demo
// capability + action config to (03 §9, 08 §9). It names the fixture
// subdirectory under fixtures/.
const DemoScenario = "lateral-movement-via-rdp"

// DemoConfigBase is the base filename (no extension) of the example capability
// and action configs under examples/{capability,action}/. It differs from
// DemoScenario: the configs are named for the workflow, the fixtures for the
// full scenario id.
const DemoConfigBase = "lateral-movement"
