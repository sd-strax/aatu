package capability

import (
	"time"

	"github.com/sd-strax/reckon/identity"
)

// DerivationMode records whether an interpretation-layer object traces to a
// direct tool observation or to an upstream inference (design/01, 03 §1).
type DerivationMode string

const (
	// DerivationDirect: the object traces to a real tool call. Every normalizer
	// output is DIRECT except the detection_finding normalizer's Indicators and
	// Sightings.
	DerivationDirect DerivationMode = "DIRECT"
	// DerivationInferred: an imported upstream inference (a vendor detection).
	// The single capability-layer exception (§4.12); never wrapped in an
	// x-interpretation here — the agent loop does that on engagement.
	DerivationInferred DerivationMode = "INFERRED"
)

// Edge (cross-layer) join types linking interpretation objects to the
// telemetry OcsfEvent they came from (design/01 two-layer graph).
const (
	EdgeExtractedFrom = "extracted-from" // SCO → OcsfEvent
	EdgeDerivedFrom   = "derived-from"   // ObservedData → OcsfEvent
)

// STIX Relationship (SRO) types produced by the v0 normalizers. parent-of is
// deliberately NOT used here — 01-domain-model.md reserves it for x-hypothesis
// refinement, distinct from parent-process-of.
const (
	RelParentProcessOf   = "parent-process-of"
	RelParentDirectoryOf = "parent-directory-of"
	RelResolvesTo        = "resolves-to"
	RelAuthenticatedTo   = "x-authenticated-to"
)

// Provenance is the uniform provenance carried by every normalizer output
// (§2.0). It records how the object came to be so the agent loop and audit can
// trust-weight it.
type Provenance struct {
	DerivationMode    DerivationMode `json:"derivation_mode"`
	Tool              string         `json:"tool"`               // source_tool the observation came through
	Normalizer        string         `json:"normalizer"`         // normalizer name (usually the OCSF class)
	NormalizerVersion int            `json:"normalizer_version"` // for re-normalization tracking
	ObservedAt        time.Time      `json:"observed_at"`        // event time
}

// SCO is a STIX cyber-observable produced by normalization: a typed entity with
// a resolver-minted identity. Properties holds the STIX-shaped fields (pid,
// value, hashes, …); identity itself is computed by the identity resolver, not
// from Properties.
type SCO struct {
	ID         identity.STIXID `json:"id"`
	Type       string          `json:"type"`
	Properties map[string]any  `json:"properties"`
	Provenance Provenance      `json:"provenance"`
}

// ObservedData is a STIX SDO grouping the entities seen in one OcsfEvent
// (design/01). object_refs points at the SCOs; the derived-from edge links it to
// the telemetry record. Extensions carries custom fields (e.g. logon_type/status
// for authentication, §4.2).
type ObservedData struct {
	ID             identity.STIXID   `json:"id"`
	FirstObserved  time.Time         `json:"first_observed"`
	LastObserved   time.Time         `json:"last_observed"`
	NumberObserved int               `json:"number_observed"`
	ObjectRefs     []identity.STIXID `json:"object_refs"`
	Extensions     map[string]any    `json:"extensions,omitempty"`
	Provenance     Provenance        `json:"provenance"`
}

// Relationship is a STIX SRO: a typed edge between two interpretation-layer
// objects (parent-process-of, resolves-to, x-authenticated-to).
type Relationship struct {
	ID         identity.STIXID `json:"id"`
	Type       string          `json:"relationship_type"`
	SourceRef  identity.STIXID `json:"source_ref"`
	TargetRef  identity.STIXID `json:"target_ref"`
	Provenance Provenance      `json:"provenance"`
}

// Edge is a cross-layer join between an interpretation object and the telemetry
// OcsfEvent it was extracted or derived from. Edges are internal join records,
// not STIX objects, so they carry no STIX id.
type Edge struct {
	Type        string          `json:"type"` // EdgeExtractedFrom | EdgeDerivedFrom
	SourceRef   identity.STIXID `json:"source_ref"`
	OcsfEventID string          `json:"ocsf_event_id"` // the telemetry record's id
}

// NormalizationResult is the full output of normalizing one OcsfEvent: the SCOs
// extracted, the ObservedData grouping them, the STIX relationships between
// them, and the cross-layer edges back to the OcsfEvent (§4).
type NormalizationResult struct {
	ObservedData  []ObservedData
	SCOs          []SCO
	Relationships []Relationship
	Edges         []Edge
}
