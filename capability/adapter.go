// Package capability is the LLM↔tool read surface (design/03-capability-layer.md):
// the transport-neutral adapter contract, the fixture adapter, normalization,
// and (later phases) the verb resolver. It is pure I/O plus normalization — it
// does not reason, never authors x-interpretation, and emits observations with
// derivation_mode = DIRECT (the single exception being the detection_finding
// normalizer, §4.12). Identity is never computed here; the normalizer delegates
// to the identity resolver, the single arbiter of STIX ids (§7.4).
package capability

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AdapterClass is operator-facing metadata (surfaced in list_capabilities) and
// a hook for shared infrastructure. The Adapter contract is identical across
// classes (§5.4).
type AdapterClass string

const (
	ClassMCP          AdapterClass = "mcp"           // wraps an MCP server
	ClassNativeAPI    AdapterClass = "native_api"    // direct vendor REST/GraphQL/gRPC
	ClassCustom       AdapterClass = "custom"        // homegrown tools, data lakes, files
	ClassSOARPlaybook AdapterClass = "soar_playbook" // delegates writes to an external orchestrator
	ClassFixture      AdapterClass = "fixture"       // v0 replay/testing (special case of custom)
)

// ErrorClass tells the resolver how to react to an adapter failure (§6.2).
type ErrorClass string

const (
	// ErrRetry is transient — the same call might succeed if repeated (rate
	// limit, network blip, vendor 5xx). The resolver does not retry within one
	// capability call; it falls through.
	ErrRetry ErrorClass = "RETRY"
	// ErrFallthrough means this binding cannot service this call but another
	// might (auth scope, "no data for this device", schema mismatch). The
	// resolver moves to the next-priority binding.
	ErrFallthrough ErrorClass = "FALLTHROUGH"
	// ErrUnhealthy means the adapter as a whole is currently unusable (bad
	// credentials, API unreachable). Remaining bindings on it are skipped for
	// the rest of the call.
	ErrUnhealthy ErrorClass = "UNHEALTHY"
	// ErrFatal means continuing would corrupt state or violate an invariant.
	// Rare; represents a bug, not an operational condition.
	ErrFatal ErrorClass = "FATAL"
)

// AdapterError carries an ErrorClass so the resolver can branch on it. Use
// errors.As to recover the classification; an unclassified error from Invoke is
// treated as ErrFallthrough by the resolver (the safe default).
type AdapterError struct {
	Class ErrorClass
	Err   error
}

func (e *AdapterError) Error() string {
	return fmt.Sprintf("%s: %v", e.Class, e.Err)
}

func (e *AdapterError) Unwrap() error { return e.Err }

// adapterErrorf builds a classified AdapterError.
func adapterErrorf(class ErrorClass, format string, args ...any) *AdapterError {
	return &AdapterError{Class: class, Err: fmt.Errorf(format, args...)}
}

// OcsfPayload is one OCSF-shaped event produced by an adapter. The adapter is
// responsible for OCSF shaping regardless of class — by the time data crosses
// the adapter boundary it is OCSF (§5.4).
type OcsfPayload struct {
	ClassUID  int            // OCSF class_uid (e.g. 3002 authentication)
	ClassName string         // OCSF class_name
	Time      time.Time      // event time from the OCSF payload
	Raw       map[string]any // the full OCSF event body, untouched
}

// AdapterResponse is the whole result of one Invoke: zero or more OCSF events
// plus the source-tool label they were observed through. (The §5.3 interface
// returns a single AdapterResponse per call; a list verb's many events ride in
// Events — the spec does not fix AdapterResponse's fields.)
type AdapterResponse struct {
	// SourceTool labels every produced OcsfEvent, e.g.
	// "fixture:lateral-movement-via-rdp" or "crowdstrike_falcon".
	SourceTool string
	Events     []OcsfPayload
}

// HealthStatus is an adapter's current health, surfaced in list_capabilities.
type HealthStatus struct {
	Healthy bool
	Message string
}

// Adapter is the transport-neutral contract every integration implements
// (§5.3). In-tree adapters self-register; out-of-process adapters are reached
// over their protocol. Either way, dispatch is uniform.
type Adapter interface {
	// Name is the adapter instance name (e.g. "fixture", "crowdstrike_falcon").
	Name() string
	// Class is one of the five AdapterClass values.
	Class() AdapterClass
	// SupportedOperations lists the operation names this adapter exposes.
	SupportedOperations() []string
	// Invoke runs one operation with binding-templated params and returns the
	// OCSF-shaped result. On failure it returns an *AdapterError.
	Invoke(ctx context.Context, operation string, params map[string]any) (AdapterResponse, error)
	// Health reports current readiness.
	Health() HealthStatus
}

// OcsfEvent is an immutable telemetry-layer record: one raw OCSF event as
// observed through an adapter (design/01 telemetry layer). ID and RecordedAt
// are infrastructure identity minted at ingest; STIX identity for the
// interpretation layer is computed later, only in the normalizer.
type OcsfEvent struct {
	ID         uuid.UUID      // telemetry-record PK (not a STIX id)
	ClassUID   int            // OCSF class_uid
	ClassName  string         // OCSF class_name
	Time       time.Time      // when the event occurred (from the payload)
	RecordedAt time.Time      // when reckon ingested it
	SourceTool string         // adapter identity / "fixture:<scenario>"
	Payload    map[string]any // raw OCSF, untouched
}

// ToOcsfEvents converts an AdapterResponse into immutable telemetry records,
// minting a fresh UUIDv7 id and stamping recordedAt on each.
func (resp AdapterResponse) ToOcsfEvents(recordedAt time.Time) []OcsfEvent {
	out := make([]OcsfEvent, 0, len(resp.Events))
	for _, e := range resp.Events {
		out = append(out, OcsfEvent{
			ID:         uuid.Must(uuid.NewV7()),
			ClassUID:   e.ClassUID,
			ClassName:  e.ClassName,
			Time:       e.Time,
			RecordedAt: recordedAt,
			SourceTool: resp.SourceTool,
			Payload:    e.Raw,
		})
	}
	return out
}
