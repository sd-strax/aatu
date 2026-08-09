package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
)

const version = "0.1.0"

// stateClosed is the ServiceNow incident state for Closed, given as the choice
// LABEL because writes go through sysparm_input_display_value=true (see
// writeQuery). ticket.close is a forward transition to this state, never a
// reversal of ticket.create (04 §2.2).
const stateClosed = "Closed"

// defaultCloseCode is used when ticket.close carries no close_code. ServiceNow's
// close business rule requires a code + notes; this keeps a bare close valid.
const defaultCloseCode = "Closed/Resolved by Caller"

// bridge holds the instance config and the native ServiceNow client. It serves
// both surfaces: the write-side ticketing family (dispatch) and, since Phase F,
// the read-side external-case verbs (invoke — query_external_cases /
// get_external_case_details, 03 §2.9), which read the incident table's cases
// back as class-2005 OCSF Incident Findings.
type bridge struct {
	mu     sync.Mutex
	client *snowClient
}

func newBridge() *bridge { return &bridge{} }

func (b *bridge) Close() {}

// handle dispatches one reckon plugin protocol method.
func (b *bridge) handle(ctx context.Context, method string, params []byte) (any, *wireError) {
	switch method {
	case "initialize":
		return adapterplugin.InitializeResult{ProtocolVersion: adapterplugin.ProtocolVersion, AdapterVersion: version, Concurrency: 1}, nil
	case "describe":
		return describe(), nil
	case "configure":
		return b.configure(params)
	case "dispatch":
		return b.dispatch(ctx, params)
	case "health":
		return b.health(), nil
	case "invoke":
		return b.invoke(ctx, params)
	default:
		return nil, &wireError{Code: -32601, Message: "unknown method " + method}
	}
}

// configure validates + stores the instance config (11 §4.3). password is an
// x-secret field the host resolved to plaintext before delivery; it lives only
// in this process's memory (there is no child — this adapter is the native
// client).
func (b *bridge) configure(params []byte) (any, *wireError) {
	var p adapterplugin.ConfigureParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &wireError{Code: -32602, Message: "configure params: " + err.Error()}
	}
	instanceURL, _ := p.Config["instance_url"].(string)
	username, _ := p.Config["username"].(string)
	password, _ := p.Config["password"].(string)
	if instanceURL == "" || username == "" || password == "" {
		return nil, &wireError{Code: -32602, Message: "configure requires instance_url, username and password"}
	}
	table, _ := p.Config["table"].(string)

	b.mu.Lock()
	b.client = newSnowClient(instanceURL, username, password, table)
	b.mu.Unlock()
	return map[string]any{"ok": true}, nil
}

// invoke performs one read operation against the incident table (03 §2.9). Each
// incident is shaped into a class-2005 OCSF Incident Finding the engine-side
// caseNormalizer turns into an ObservedData. Read failures map onto the 03 §6.2
// taxonomy via classErr (a not-found case is FALLTHROUGH, a down instance is
// UNHEALTHY).
func (b *bridge) invoke(ctx context.Context, params []byte) (any, *wireError) {
	var p adapterplugin.InvokeParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, classErr(-32602, "invoke params: "+err.Error(), string(capability.ErrFallthrough))
	}

	b.mu.Lock()
	client := b.client
	b.mu.Unlock()
	if client == nil {
		return nil, classErr(-32000, "adapter not configured", string(capability.ErrUnhealthy))
	}

	switch p.Operation {
	case "get_incident":
		return b.getIncident(ctx, client, p.Params)
	case "query_incidents":
		return b.queryIncidents(ctx, client, p.Params)
	default:
		return nil, classErr(-32602, "unknown read operation "+p.Operation, string(capability.ErrFallthrough))
	}
}

// getIncident serves get_external_case_details: resolve one case by id/number
// and return its single class-2005 event.
func (b *bridge) getIncident(ctx context.Context, client *snowClient, params map[string]any) (any, *wireError) {
	id, _ := params["case_id"].(string)
	if id == "" {
		return nil, classErr(-32602, "get_incident requires case_id", string(capability.ErrFallthrough))
	}
	rec, status, err := client.getIncidentByID(ctx, id)
	if err != nil {
		return nil, classErr(-32000, err.Error(), readClass(status))
	}
	if rec == nil {
		return nil, classErr(-32602, "no case matches "+id, string(capability.ErrFallthrough))
	}
	return invokeResult{
		SourceTool: "servicenow",
		Events:     []ocsfEvent{toWire(b.caseToOcsf(rec))},
	}, nil
}

// queryIncidents serves query_external_cases: translate the free-text filter and
// status into a ServiceNow encoded query, fetch the matching cases, and shape
// each into a class-2005 event. An empty result set is a valid (empty) response
// — evidence of absence, not an error.
func (b *bridge) queryIncidents(ctx context.Context, client *snowClient, params map[string]any) (any, *wireError) {
	var clauses []string
	if filter, _ := params["filter"].(string); filter != "" {
		clauses = append(clauses, "short_descriptionLIKE"+filter)
	}
	if status, _ := params["status"].(string); status != "" {
		clauses = append(clauses, "state="+status)
	}
	encoded := strings.Join(clauses, "^")

	limit := 50
	if v, ok := readInt(params["limit"]); ok && v > 0 {
		limit = v
	}
	if limit > 200 {
		limit = 200
	}

	recs, status, err := client.queryIncidents(ctx, encoded, limit)
	if err != nil {
		return nil, classErr(-32000, err.Error(), readClass(status))
	}
	events := make([]ocsfEvent, 0, len(recs))
	for _, rec := range recs {
		events = append(events, toWire(b.caseToOcsf(rec)))
	}
	return invokeResult{SourceTool: "servicenow", Events: events}, nil
}

// caseToOcsf shapes a Table API incident record into the class-2005 payload the
// engine-side caseNormalizer reads (finding_info.uid/title/desc, status,
// priority, assignment_group, unmapped.link/sor). With the caseFields column set
// the display values come back as plain strings, so a `.(string)` coercion is
// safe (empty on any surprise reference object).
func (b *bridge) caseToOcsf(rec map[string]any) capability.OcsfPayload {
	s := func(k string) string { v, _ := rec[k].(string); return v }
	link := ""
	if b.client != nil && s("sys_id") != "" {
		link = b.client.baseURL + "/nav_to.do?uri=incident.do?sys_id=" + s("sys_id")
	}
	raw := map[string]any{
		"class_uid":        2005,
		"status":           s("state"),
		"priority":         s("priority"),
		"assignment_group": s("assignment_group"),
		"finding_info": map[string]any{
			"uid":   s("number"),
			"title": s("short_description"),
			"desc":  s("description"),
		},
		"unmapped": map[string]any{"link": link, "sor": "servicenow", "sys_id": s("sys_id")},
	}
	return capability.OcsfPayload{ClassUID: 2005, ClassName: "Incident Finding", Time: parseSnowTime(s("opened_at")), Raw: raw}
}

// readClass maps an HTTP status from a read call onto the 03 §6.2 taxonomy: a
// transport failure (0), 429, or 5xx is retryable; a definitive 4xx falls
// through so the resolver can try another binding.
func readClass(status int) string {
	if status == 0 || status == 429 || status >= 500 {
		return string(capability.ErrRetry)
	}
	return string(capability.ErrFallthrough)
}

// readInt coerces a templated limit param (JSON numbers decode to float64;
// strings may arrive from a text-only template render).
func readInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

// parseSnowTime parses a ServiceNow display datetime ("2006-01-02 15:04:05",
// UTC). On any parse failure it returns the zero time.
func parseSnowTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC)
	if err != nil {
		return time.Time{}
	}
	return t
}

// invokeResult is the reckon-plugin invoke result wire shape (matches the host's
// decoder in internal/adapterplugin). capability.OcsfPayload has no JSON tags of
// its own, so the events are re-shaped onto ocsfEvent for the wire.
type invokeResult struct {
	SourceTool string      `json:"source_tool"`
	Events     []ocsfEvent `json:"events"`
}

type ocsfEvent struct {
	ClassUID  int            `json:"class_uid"`
	ClassName string         `json:"class_name"`
	Time      time.Time      `json:"time"`
	Raw       map[string]any `json:"raw"`
}

func toWire(p capability.OcsfPayload) ocsfEvent {
	return ocsfEvent{ClassUID: p.ClassUID, ClassName: p.ClassName, Time: p.Time, Raw: p.Raw}
}

// dispatch performs one ticketing operation against the incident table. The
// engine resolved the target at request time (08 §4) and froze the params via
// the binding template; the adapter never re-resolves an entity, only maps a
// display number to its sys_id (a ServiceNow addressing detail, not a
// re-resolution).
func (b *bridge) dispatch(ctx context.Context, params []byte) (any, *wireError) {
	var p adapterplugin.DispatchParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, classErr(-32602, "dispatch params: "+err.Error(), string(action.WriteFatal))
	}

	b.mu.Lock()
	client := b.client
	b.mu.Unlock()
	if client == nil {
		return nil, classErr(-32000, "adapter not configured", string(action.WriteFatal))
	}

	switch p.Operation {
	case "create_incident":
		return b.createIncident(ctx, client, p)
	case "add_comment":
		return b.patchOp(ctx, client, p, func(map[string]any) {})
	case "set_state":
		return b.patchOp(ctx, client, p, func(map[string]any) {})
	case "close_incident":
		return b.patchOp(ctx, client, p, func(fields map[string]any) {
			fields["state"] = stateClosed
			if _, ok := fields["close_code"]; !ok {
				fields["close_code"] = defaultCloseCode
			}
		})
	default:
		return nil, classErr(-32602, "unknown write operation "+p.Operation+" (create_incident | add_comment | set_state | close_incident)", string(action.WriteFatal))
	}
}

// createIncident opens a new incident, idempotently against the dispatch
// idempotency key (08 §6a): the key is stamped on the record's correlation_id,
// and a lookup precedes the POST so a retry-in-budget returns the existing
// incident instead of opening a duplicate. The per-target key is the destination
// queue (the resolved target); the created number rides back on RawResponseRef
// as the operational reference the analyst follows.
func (b *bridge) createIncident(ctx context.Context, client *snowClient, p adapterplugin.DispatchParams) (any, *wireError) {
	target := targetKey(p.Params)

	// Idempotency: has this exact dispatch already created an incident?
	if p.IdempotencyKey != "" {
		existing, status, err := client.findOne(ctx, "correlation_id="+p.IdempotencyKey)
		if err != nil {
			return b.resultFromErr(target, p.IdempotencyKey, status, err), nil
		}
		if existing != nil {
			return okResult(target, p.IdempotencyKey, existing.Number), nil
		}
	}

	fields := bodyFields(p.Params, createSkip)
	if p.IdempotencyKey != "" {
		fields["correlation_id"] = p.IdempotencyKey
	}

	rec, status, err := client.createIncident(ctx, fields)
	if err != nil {
		return b.resultFromErr(target, p.IdempotencyKey, status, err), nil
	}
	return okResult(target, p.IdempotencyKey, rec.Number), nil
}

// patchOp resolves the target incident to its sys_id and PATCHes the remaining
// params as fields, after mutate has stamped any op-specific fields (state/close
// code). The ticket identifier key is stripped from the body — it addresses the
// record, it is not a field on it.
func (b *bridge) patchOp(ctx context.Context, client *snowClient, p adapterplugin.DispatchParams, mutate func(map[string]any)) (any, *wireError) {
	identifier := recordIdentifier(p.Params)
	target := identifier
	if identifier == "" {
		return failResult(target, p.IdempotencyKey, action.WriteFatal,
			p.Operation+" requires a target incident (sys_id or number)"), nil
	}

	sysID, status, err := client.resolveSysID(ctx, identifier)
	if err != nil {
		return b.resultFromErr(target, p.IdempotencyKey, status, err), nil
	}
	if sysID == "" {
		return failResult(target, p.IdempotencyKey, action.WriteFatal,
			fmt.Sprintf("no incident matches %q", identifier)), nil
	}

	fields := bodyFields(p.Params, recordKeys)
	mutate(fields)
	if len(fields) == 0 {
		return failResult(target, p.IdempotencyKey, action.WriteFatal,
			p.Operation+" resolved no fields to write"), nil
	}

	_, status, err = client.patchIncident(ctx, sysID, fields)
	if err != nil {
		return b.resultFromErr(target, p.IdempotencyKey, status, err), nil
	}
	return okResult(target, p.IdempotencyKey, identifier), nil
}

// resultFromErr classifies an HTTP-error dispatch outcome (08 §6c). A transport
// failure carried status 0 and is UNKNOWN/RETRYABLE (the write may have landed).
// A 429 or 5xx is server-ambiguous — also UNKNOWN/RETRYABLE, safe because
// create dedups on correlation_id and the PATCH ops are state-convergent. A
// definitive 4xx (auth, validation, not-found) is FAIL/FATAL.
func (b *bridge) resultFromErr(target, idemKey string, status int, err error) action.WriteResult {
	if status == 0 || status == 429 || status >= 500 {
		return unknownResult(target, idemKey, err)
	}
	return failResult(target, idemKey, action.WriteFatal, err.Error())
}

// --- WriteResult constructors ---

func okResult(target, idemKey, ref string) action.WriteResult {
	return action.WriteResult{
		FinalOutcome:     action.OutcomeSucceeded,
		PerTargetResults: map[string]action.PerTargetResult{target: action.TargetOK},
		AdapterRequestID: idemKey,
		AuditDepth:       action.AuditFull,
		RawResponseRef:   ref,
	}
}

func failResult(target, idemKey string, class action.WriteErrorClass, detail string) action.WriteResult {
	return action.WriteResult{
		FinalOutcome:     action.OutcomeFailed,
		PerTargetResults: map[string]action.PerTargetResult{target: action.TargetFail},
		AdapterRequestID: idemKey,
		ErrorClass:       class,
		ErrorDetail:      detail,
		AuditDepth:       action.AuditFull,
	}
}

func unknownResult(target, idemKey string, err error) action.WriteResult {
	return action.WriteResult{
		FinalOutcome:     action.OutcomeFailed,
		PerTargetResults: map[string]action.PerTargetResult{target: action.TargetUnknown},
		AdapterRequestID: idemKey,
		ErrorClass:       action.WriteRetryable,
		ErrorDetail:      err.Error(),
		AuditDepth:       action.AuditFull,
	}
}

type healthResult struct {
	Healthy bool   `json:"healthy"`
	Message string `json:"message"`
}

// health reports readiness: configured is healthy (Basic auth is validated
// lazily at first dispatch, where a bad credential surfaces as a 401 FAIL).
func (b *bridge) health() healthResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.client == nil {
		return healthResult{Healthy: false, Message: "not configured"}
	}
	return healthResult{Healthy: true, Message: "configured (ServiceNow Table API, " + b.client.baseURL + ")"}
}

// recordKeys are the params that address the incident (not fields on it) plus
// the reckon protocol params the resolver injects (action_type, and the
// targets[0] convenience copy resolved_identifier); all are stripped from a
// PATCH body — writing protocol fields into an external system of record is
// junk today and a column collision tomorrow. Order in recordIdentifier is the
// lookup preference.
var recordKeys = map[string]bool{
	"ticket": true, "sys_id": true, "resolved_identifier": true, "number": true, "id": true,
	"action_type": true,
}

// createSkip strips the protocol params from a create body: action_type is
// reckon routing metadata, and resolved_identifier duplicates the
// assignment_group the binding already mapped.
var createSkip = map[string]bool{"action_type": true, "resolved_identifier": true}

// recordIdentifier extracts the target incident identifier the engine froze at
// request time (08 §4 — the adapter never re-resolves the entity).
func recordIdentifier(params map[string]any) string {
	for _, k := range []string{"ticket", "sys_id", "resolved_identifier", "number", "id"} {
		if v, ok := params[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// targetKey is the per-target result key for a create: the destination queue the
// incident was routed to, falling back to a stable label.
func targetKey(params map[string]any) string {
	for _, k := range []string{"assignment_group", "resolved_identifier"} {
		if v, ok := params[k].(string); ok && v != "" {
			return v
		}
	}
	return "incident"
}

// bodyFields builds the Table API write body from templated params: every
// non-empty value, excluding any addressing keys in skip. Empty strings are
// dropped so an unpopulated optional (e.g. description) never blanks a field.
func bodyFields(params map[string]any, skip map[string]bool) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		if skip[k] {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		if v == nil {
			continue
		}
		out[k] = v
	}
	return out
}
