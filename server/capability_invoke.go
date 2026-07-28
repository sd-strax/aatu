package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/capability"
)

// maxCapabilityBodyBytes bounds the /api/capability/{verb} request body. Verb
// inputs are an entity, a window, and small extras — far below this; the bound
// exists so a buggy or hostile client cannot stream an unbounded body.
const maxCapabilityBodyBytes = 1 << 20 // 1 MiB

// CapabilityInvokeBody is a verb call's input (03 §2): the entity the binding
// templates resolve against, an optional time window, and extra template roots.
type CapabilityInvokeBody struct {
	Entity map[string]any `json:"entity,omitempty"`
	Window *WindowInput   `json:"window,omitempty"`
	Extra  map[string]any `json:"extra,omitempty"`
}

// WindowInput is the JSON shape of a verb call's time bound.
type WindowInput struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// OcsfEventView is the wire shape of one telemetry record returned by an
// invocation. Telemetry persistence is deferred (Phase E.1 returns the envelope
// only), so the payload rides the response — the caller is the only consumer.
type OcsfEventView struct {
	ID         string         `json:"id"`
	ClassUID   int            `json:"class_uid"`
	ClassName  string         `json:"class_name"`
	Time       time.Time      `json:"time"`
	RecordedAt time.Time      `json:"recorded_at"`
	SourceTool string         `json:"source_tool"`
	Payload    map[string]any `json:"payload"`
}

// NormalizedView is the wire shape of one event's normalization output (03 §4).
type NormalizedView struct {
	ObservedData  []capability.ObservedData   `json:"observed_data,omitempty"`
	SCOs          []capability.SCO            `json:"scos,omitempty"`
	Relationships []capability.Relationship   `json:"relationships,omitempty"`
	Edges         []capability.Edge           `json:"edges,omitempty"`
	Indicators    []capability.Indicator      `json:"indicators,omitempty"`
	Sightings     []capability.Sighting       `json:"sightings,omitempty"`
	Identities    []capability.VendorIdentity `json:"identities,omitempty"`
}

// CapabilityInvokeResponse is the CapabilityResult envelope (03 §2, §6.1): the
// reference lists the agent loop attaches to an x-interpretation, the coverage
// classification, degradation notes, and the concrete objects produced.
type CapabilityInvokeResponse struct {
	Verb             string           `json:"verb"`
	Coverage         string           `json:"coverage"`
	OcsfEventRefs    []string         `json:"ocsf_event_refs,omitempty"`
	ObservedDataRefs []string         `json:"observed_data_refs,omitempty"`
	EntityRefs       []string         `json:"entity_refs,omitempty"`
	DegradationNotes []string         `json:"degradation_notes,omitempty"`
	Events           []OcsfEventView  `json:"events,omitempty"`
	Normalized       []NormalizedView `json:"normalized,omitempty"`
}

// capabilityInvokeRoute handles POST /api/capability/{verb} (03 §3.4, 05 §6.1):
// the agent loop's read-tool dispatch target. Analyst role — invocation causes
// outbound tool I/O, unlike the read-only catalog at /api/capabilities. Reads
// are T0: an AI-delegated token invokes freely (the write path has the gates).
func (b *Backend) capabilityInvokeRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if b.cfg.CapabilityResolver == nil || b.cfg.CapabilityCatalog == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "capability layer not configured")
		return
	}
	b.requireRolesOrDeny(w, r, []string{authz.RoleAnalyst}, b.capabilityInvoke)
}

// capabilityInvoke executes one verb call: resolve the verb against the
// catalog, decode the CallInput, run the resolver, and return the envelope.
// Coverage — including UNAVAILABLE_* — is a 200: the call executed and the
// envelope's classification IS the result (03 §6.1). Non-200s are reserved for
// the call not executing: unknown verb (404), bad input (400), adapter FATAL
// (502 — upstream tool failure), template render (500 — config bug).
func (b *Backend) capabilityInvoke(w http.ResponseWriter, r *http.Request) {
	verb, ok := capabilityVerbFromPath(r.URL.Path)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "path must be /capability/{verb}")
		return
	}
	if _, known := b.cfg.CapabilityCatalog.Descriptor(verb); !known {
		writeJSONError(w, http.StatusNotFound, "unknown verb "+verb)
		return
	}

	var body CapabilityInvokeBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCapabilityBodyBytes))
	if err := dec.Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}

	input := capability.CallInput{Entity: body.Entity, Extra: body.Extra}
	if body.Window != nil {
		input.Window = capability.TimeWindow{From: body.Window.From, To: body.Window.To}
	}

	res, err := b.cfg.CapabilityResolver.Resolve(r.Context(), verb, input)
	if err != nil {
		var ae *capability.AdapterError
		if errors.As(err, &ae) {
			// FATAL adapter error: the upstream tool cannot service the call.
			writeJSONError(w, http.StatusBadGateway, verb+": "+err.Error())
			return
		}
		// Template render failure — a tenant-config bug, not the caller's.
		writeJSONError(w, http.StatusInternalServerError, verb+": "+err.Error())
		return
	}

	// Eager promotion at ingest (03 §4.13): the telemetry + normalized objects
	// are persisted before the refs leave the building — a ref the caller cites
	// must be openable later (design/ui 02 §2.8). Persist failure fails the
	// invocation rather than minting dangling citations.
	if b.cfg.Handler != nil {
		if err := persistInvokeResult(r, b.cfg.Handler.DB(), res); err != nil {
			writeJSONError(w, http.StatusInternalServerError, verb+": persist results: "+err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, buildInvokeResponse(verb, res))
}

// buildInvokeResponse converts the resolver's CapabilityResult to the wire
// envelope.
func buildInvokeResponse(verb string, res capability.CapabilityResult) CapabilityInvokeResponse {
	out := CapabilityInvokeResponse{
		Verb:             verb,
		Coverage:         string(res.Coverage),
		OcsfEventRefs:    res.OcsfEventRefs,
		DegradationNotes: res.DegradationNotes,
	}
	for _, ref := range res.ObservedDataRefs {
		out.ObservedDataRefs = append(out.ObservedDataRefs, string(ref))
	}
	for _, ref := range res.EntityRefs {
		out.EntityRefs = append(out.EntityRefs, string(ref))
	}
	for _, e := range res.Events {
		out.Events = append(out.Events, OcsfEventView{
			ID:         e.ID.String(),
			ClassUID:   e.ClassUID,
			ClassName:  e.ClassName,
			Time:       e.Time,
			RecordedAt: e.RecordedAt,
			SourceTool: e.SourceTool,
			Payload:    e.Payload,
		})
	}
	for _, n := range res.Normalized {
		out.Normalized = append(out.Normalized, NormalizedView{
			ObservedData:  n.ObservedData,
			SCOs:          n.SCOs,
			Relationships: n.Relationships,
			Edges:         n.Edges,
			Indicators:    n.Indicators,
			Sightings:     n.Sightings,
			Identities:    n.Identities,
		})
	}
	return out
}

// capabilityVerbFromPath parses the verb out of `/capability/{verb}` (the /api
// prefix is already stripped).
func capabilityVerbFromPath(p string) (string, bool) {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) != 2 || parts[0] != "capability" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}
