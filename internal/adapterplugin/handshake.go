package adapterplugin

import (
	"time"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
)

// Method names, mapped 1:1 onto JSON-RPC methods (§2 "invoke/dispatch/health
// mapped 1:1"). The handshake trio (initialize/describe/configure) runs once
// per process lifetime; the serve trio (invoke/dispatch/health) runs per call.
const (
	methodInitialize = "initialize"
	methodDescribe   = "describe"
	methodConfigure  = "configure"
	methodInvoke     = "invoke"
	methodDispatch   = "dispatch"
	methodHealth     = "health"
)

// InitializeParams is the first call after spawn (§4.1). Version negotiation is
// the highest protocol version both sides support.
type InitializeParams struct {
	EngineProtocolVersions []int  `json:"engine_protocol_versions"`
	EngineVersion          string `json:"engine_version"`
}

// InitializeResult is the adapter's negotiation reply (§4.1). Concurrency is the
// adapter's declared parallelism; the default (and a valid answer for a
// single-threaded script) is serial.
type InitializeResult struct {
	ProtocolVersion int    `json:"protocol_version"`
	AdapterVersion  string `json:"adapter_version"`
	Concurrency     int    `json:"concurrency"`
}

// DescribeResult is the source of truth on capability (§4.2). The engine
// disposes of what it proposes: descriptors and default bindings enter the
// registries as CANDIDATES, filtered by enablement before an agent can see them
// (§5). Two hard rules from §4.2 apply when this is reconciled into the
// catalog: the adapter is the authority on capability FACTS (which ops exist,
// their schemas, which inverse op exists) but NEVER on tier or reversibility
// CLASSIFICATION — those are engine-side risk judgments (04 §2), and a
// conflicting adapter claim is a drift signal surfaced at enablement, never
// silently adopted.
//
// Read and write default bindings are carried under separate keys because their
// shapes differ (an ActionBinding declares external-approval substitution); a
// single adapter of class mcp may legitimately describe both (e.g. CRWD-falcon:
// read verbs plus ioc.block).
type DescribeResult struct {
	Verbs                []capability.CapabilityDescriptor `json:"verbs"`
	ActionTypes          []action.ActionDescriptor         `json:"action_types"`
	Operations           []OperationSchema                 `json:"operations"`
	DefaultReadBindings  []ReadBinding                     `json:"default_read_bindings"`
	DefaultWriteBindings []action.ActionBinding            `json:"default_write_bindings"`
	ConfigSchema         map[string]any                    `json:"config_schema"`
}

// ReadBinding is a default read-verb binding in describe output (§4.2), ready to
// adopt into tenant config. Unlike a bare capability.Binding it carries the Verb
// it binds — the tenant config keys bindings by verb (03 §3.2), and the write
// side already carries its ActionType on action.ActionBinding.
type ReadBinding struct {
	Verb      string         `json:"verb"`
	Adapter   string         `json:"adapter"`
	Operation string         `json:"operation"`
	Priority  int            `json:"priority,omitempty"`
	Params    map[string]any `json:"params,omitempty"`
}

// OperationSchema names an operation invoke/dispatch will accept and its param
// schema (§4.2). The operation name is what a binding's `operation` field
// references (03 §3.2 / 08 §4).
type OperationSchema struct {
	Name   string         `json:"name"`
	Params map[string]any `json:"params"`
}

// ConfigureParams delivers the instance's validated config as the final
// handshake step (§4.3). x-secret fields carry UNRESOLVED secret references
// (keychain:// / env:// / vault://), never literals — resolution is
// per-invocation (05 §10.2) and a literal is refused at config load.
type ConfigureParams struct {
	Config map[string]any `json:"config"`
}

// InvokeParams runs one read operation with binding-templated params (§4,
// mapping capability.Adapter.Invoke).
type InvokeParams struct {
	Operation string         `json:"operation"`
	Params    map[string]any `json:"params"`
}

// invokeResult is the wire shape of one Invoke: OCSF events plus their
// source-tool label. It maps onto capability.AdapterResponse.
type invokeResult struct {
	SourceTool string            `json:"source_tool"`
	Events     []ocsfPayloadWire `json:"events"`
}

// ocsfPayloadWire is the wire shape of capability.OcsfPayload (which has no JSON
// tags of its own — it is an in-process type).
type ocsfPayloadWire struct {
	ClassUID  int            `json:"class_uid"`
	ClassName string         `json:"class_name"`
	Time      time.Time      `json:"time"`
	Raw       map[string]any `json:"raw"`
}

func (w invokeResult) toResponse() capability.AdapterResponse {
	events := make([]capability.OcsfPayload, 0, len(w.Events))
	for _, e := range w.Events {
		events = append(events, capability.OcsfPayload{
			ClassUID:  e.ClassUID,
			ClassName: e.ClassName,
			Time:      e.Time,
			Raw:       e.Raw,
		})
	}
	return capability.AdapterResponse{SourceTool: w.SourceTool, Events: events}
}

// DispatchParams runs one write operation (§4, mapping action.WriteAdapter.
// Dispatch). The idempotency key is mandatory (08 §6a); the adapter must dedup
// a re-issue on it.
type DispatchParams struct {
	Operation      string         `json:"operation"`
	Params         map[string]any `json:"params"`
	IdempotencyKey string         `json:"idempotency_key"`
}

// healthResult is the wire shape of capability.HealthStatus.
type healthResult struct {
	Healthy bool   `json:"healthy"`
	Message string `json:"message"`
}

// errorData is the optional `data` on a JSON-RPC error from invoke/dispatch: the
// reckon error class the adapter reports (§4, mapping 03 §6.2 for reads and
// 08 §5 for writes). A read class is one of RETRY/FALLTHROUGH/UNHEALTHY/FATAL;
// a write class is RETRYABLE_ERROR/FATAL_ERROR. An absent class is treated as
// the safe default by the host (FALLTHROUGH for reads, FATAL_ERROR for writes).
type errorData struct {
	Class string `json:"class"`
}
