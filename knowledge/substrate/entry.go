package substrate

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Archetype is the kind of corpus (00-substrate §2.2). Two, deliberately no
// more: curated standing knowledge and derived case knowledge.
type Archetype string

const (
	// Curated is human-authored standing knowledge with authoring governance.
	Curated Archetype = "CURATED"
	// Derived is machine-extracted case knowledge stamped with provenance.
	Derived Archetype = "DERIVED"
)

// Governance is the curated authoring mode (§4). Derived corpora are
// implicitly lightweight.
type Governance string

const (
	// Lightweight publishes on write; PUBLISHED → RETIRED is the only transition.
	Lightweight Governance = "LIGHTWEIGHT"
	// Gated runs DRAFT → IN_REVIEW → PUBLISHED with ≥1 recorded signer.
	Gated Governance = "GATED"
)

// Status is an entry's lifecycle state (§2.3, §4).
type Status string

const (
	StatusDraft     Status = "DRAFT"
	StatusInReview  Status = "IN_REVIEW"
	StatusPublished Status = "PUBLISHED"
	StatusRetired   Status = "RETIRED"
)

// CorpusDef declares a corpus at deployment time (§2.2). There is no
// schema-definition machinery: corpora differ only in archetype and
// governance; per-domain structure lives in tags and meta on each entry.
type CorpusDef struct {
	Name       string
	Archetype  Archetype
	Governance Governance // curated only; ignored (implicitly lightweight) for derived
}

// Provenance stamps a derived entry with where it came from (§2.3).
type Provenance struct {
	Producer        string `json:"producer"`
	ProducerVersion string `json:"producer_version"`
	GeneratorModel  string `json:"generator_model,omitempty"` // if an LLM was involved
	SourceRef       string `json:"source_ref,omitempty"`      // consumer-side pointer, opaque here
}

// Entry is one stored document (§2.3). Identity is a random v4 minted by the
// store — entries are documents, not observable facts; deduplication is a
// recall concern (similarity bands), never an identity concern.
type Entry struct {
	ID        uuid.UUID
	Namespace string
	Corpus    string

	// Content — exactly the fields covered by the content hash (§3).
	Title  string
	Body   string         // unparsed prose; never executed or interpreted
	Tags   []string       // hard-filterable facets
	Meta   map[string]any // opaque structured metadata
	Advice string         // structured hint token, consumer-interpreted

	Status       Status
	Revision     int       // monotonic within a lineage, starts at 1
	Supersedes   uuid.UUID // previous revision's entry id; Nil for revision 1
	VersionLabel string    // corpus convention (e.g. semver); not interpreted

	// Curated governance.
	AuthoredBy string   // opaque principal
	SignedOffBy []string // opaque principals recorded at the PUBLISHED transition

	// Derived provenance.
	Provenance *Provenance

	ContentHash ContentHash
	HashVersion int

	Created      time.Time
	Updated      time.Time
	PublishedAt  *time.Time
	RetiredAt    *time.Time
	SupersededAt *time.Time
}

// Revision is the content of a new revision (§4). It creates a new entry row;
// the prior revision's content stays hash-addressable.
type Revision struct {
	Title        string
	Body         string
	Tags         []string
	Meta         map[string]any
	Advice       string
	VersionLabel string
	AuthoredBy   string      // curated
	Provenance   *Provenance // derived; nil keeps the prior revision's stamp
}

// Transition carries a target status and the acting principal(s) (§7). The
// store validates the state machine per the corpus's governance mode — whether
// the principal was entitled to act is the deployment's concern, not ours.
type Transition struct {
	To         Status
	Principals []string
}

// ListFilter narrows List. Zero value: latest published/draft/in-review
// revisions only (no retired, no superseded), no tag filter, no cap.
type ListFilter struct {
	Status            Status // exact status; empty = any non-retired
	Tag               string // entries carrying this tag
	IncludeRetired    bool
	IncludeSuperseded bool
	Limit             int // 0 = no cap
	Offset            int
}

// Sentinel errors. Callers branch with errors.Is.
var (
	ErrNotFound       = errors.New("substrate: entry not found")
	ErrUnknownCorpus  = errors.New("substrate: corpus not declared")
	ErrBadTransition  = errors.New("substrate: transition not allowed")
	ErrSignerRequired = errors.New("substrate: gated publish requires at least one signer principal")
	ErrSuperseded     = errors.New("substrate: entry already superseded by a later revision")
	ErrNoEmbedding    = errors.New("substrate: published entry lacks an embedding for the active model")
)

const maxNamespaceBytes = 128

func validNamespace(ns string) error {
	if ns == "" || len(ns) > maxNamespaceBytes {
		return fmt.Errorf("substrate: namespace must be 1–%d bytes", maxNamespaceBytes)
	}
	return nil
}
