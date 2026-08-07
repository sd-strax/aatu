package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
	"github.com/sd-strax/reckon/internal/mcpclient"
)

const version = "0.1.0"

// defaultServerCommand runs the falcon-mcp that `reckon adapter setup
// crowdstrike-falcon` provisioned into the adapter's isolated venv (validated:
// the PyPI package's console script is `falcon-mcp`). Override with the
// `server_command` config field.
var defaultServerCommand = []string{"./.venv/bin/falcon-mcp"}

// defaultBaseURL is the US-1 Falcon API cloud; tenants on other clouds set
// base_url (e.g. https://api.us-2.crowdstrike.com, https://api.eu-1.crowdstrike.com).
const defaultBaseURL = "https://api.crowdstrike.com"

// mcpModules limits the vendor server to the modules this bridge actually
// maps (FALCON_MCP_MODULES, validated in the 0.16.0 source) — the rest of its
// 25+ module surface never even loads, which keeps the tool inventory (and
// the blast radius of vendor preview churn) small.
const mcpModules = "hosts,detections,intel,ioc"

// bridge holds the instance config and the lazily-spawned MCP client to
// falcon-mcp.
type bridge struct {
	mu        sync.Mutex
	client    *mcpclient.Client
	serverCmd []string
	env       []string
	ready     bool
}

func newBridge() *bridge { return &bridge{} }

func (b *bridge) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.client != nil {
		b.client.Close()
		b.client = nil
	}
}

// handle dispatches one reckon plugin protocol method.
func (b *bridge) handle(ctx context.Context, method string, params []byte) (any, *wireError) {
	switch method {
	case "initialize":
		return adapterplugin.InitializeResult{ProtocolVersion: adapterplugin.ProtocolVersion, AdapterVersion: version, Concurrency: 1}, nil
	case "describe":
		return describe(), nil
	case "configure":
		return b.configure(params)
	case "invoke":
		return b.invoke(ctx, params)
	case "dispatch":
		return b.dispatch(ctx, params)
	case "health":
		return b.health(ctx), nil
	default:
		return nil, &wireError{Code: -32601, Message: "unknown method " + method}
	}
}

// configure validates + stores the instance config (11 §4.3). client_secret is
// an x-secret field the host has already resolved to plaintext; the bridge
// forwards it as falcon-mcp's environment and never logs it. member_cid is the
// optional child tenant (FALCON_MEMBER_CID) — the natural partner of a
// source-scoped instance (03 §3.5): one scoped instance per customer CID.
func (b *bridge) configure(params []byte) (any, *wireError) {
	var p adapterplugin.ConfigureParams
	if err := jsonUnmarshal(params, &p); err != nil {
		return nil, &wireError{Code: -32602, Message: "configure params: " + err.Error()}
	}
	clientID, _ := p.Config["client_id"].(string)
	clientSecret, _ := p.Config["client_secret"].(string)
	if clientID == "" || clientSecret == "" {
		return nil, &wireError{Code: -32602, Message: "configure requires client_id and client_secret"}
	}
	baseURL, _ := p.Config["base_url"].(string)
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	memberCID, _ := p.Config["member_cid"].(string)

	b.mu.Lock()
	defer b.mu.Unlock()
	b.serverCmd = defaultServerCommand
	if cmd := stringSlice(p.Config["server_command"]); len(cmd) > 0 {
		b.serverCmd = cmd
	}
	b.env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"FALCON_CLIENT_ID=" + clientID,
		"FALCON_CLIENT_SECRET=" + clientSecret,
		"FALCON_BASE_URL=" + baseURL,
		"FALCON_MCP_MODULES=" + mcpModules,
	}
	if memberCID != "" {
		b.env = append(b.env, "FALCON_MEMBER_CID="+memberCID)
	}
	b.ready = true
	return map[string]any{"ok": true}, nil
}

// ensureClient lazily spawns + connects the falcon-mcp MCP client.
func (b *bridge) ensureClient(ctx context.Context) (*mcpclient.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready {
		return nil, fmt.Errorf("adapter not configured")
	}
	if b.client != nil {
		return b.client, nil
	}
	c, err := mcpclient.Spawn(ctx, b.serverCmd, mcpclient.WithEnv(b.env))
	if err != nil {
		return nil, err
	}
	b.client = c
	return c, nil
}

// invoke runs a read operation: call the mapped falcon-mcp tool, normalize the
// output to OCSF.
func (b *bridge) invoke(ctx context.Context, params []byte) (any, *wireError) {
	var p adapterplugin.InvokeParams
	if err := jsonUnmarshal(params, &p); err != nil {
		return nil, classErr(-32602, "invoke params: "+err.Error(), string(capability.ErrFallthrough))
	}
	client, err := b.ensureClient(ctx)
	if err != nil {
		return nil, classErr(-32000, "falcon-mcp connect: "+err.Error(), string(capability.ErrUnhealthy))
	}
	tool, args, ok := readOp(p.Operation, p.Params)
	if !ok {
		return nil, classErr(-32602, "unknown read operation "+p.Operation, string(capability.ErrFallthrough))
	}
	res, err := client.CallTool(ctx, tool, args)
	if err != nil {
		return nil, classErr(-32000, err.Error(), string(capability.ErrRetry))
	}
	if res.IsError {
		return nil, classErr(-32000, "falcon tool "+tool+": "+res.Text(), string(capability.ErrFallthrough))
	}
	events, err := normalize(p.Operation, res.StructuredOrText())
	if err != nil {
		return nil, classErr(-32000, "normalize "+tool+": "+err.Error(), string(capability.ErrFallthrough))
	}
	return invokeResult{SourceTool: "falcon:" + tool, Events: events}, nil
}

// dispatch runs a write operation (08 §5 — an outcome, not an observation).
//
//   - add_ioc  (ioc.block): create a custom IOC with action=prevent. The type
//     is inferred from the indicator value when the binding does not supply it.
//   - remove_iocs (ioc.unblock): the vendor tool takes IOC IDs, not values, so
//     the bridge does the search-by-value → remove two-step.
func (b *bridge) dispatch(ctx context.Context, params []byte) (any, *wireError) {
	var p adapterplugin.DispatchParams
	if err := jsonUnmarshal(params, &p); err != nil {
		return nil, classErr(-32602, "dispatch params: "+err.Error(), string(action.WriteFatal))
	}
	value := resolvedTarget(p.Params)
	if value == "" {
		return nil, classErr(-32602, p.Operation+" requires a resolved target (the indicator value)", string(action.WriteFatal))
	}
	client, err := b.ensureClient(ctx)
	if err != nil {
		return nil, classErr(-32000, "falcon-mcp connect: "+err.Error(), string(action.WriteFatal))
	}

	switch p.Operation {
	case "add_ioc":
		iocType, _ := p.Params["type"].(string)
		if iocType == "" {
			iocType = inferIOCType(value)
		}
		if iocType == "" {
			return failResult(value, p.IdempotencyKey, action.WriteFatal,
				fmt.Sprintf("cannot infer IOC type of %q (want domain/ipv4/ipv6/md5/sha256)", value)), nil
		}
		args := map[string]any{
			"type":             iocType,
			"value":            value,
			"action":           "prevent", // ioc.BLOCK, not merely detect
			"applied_globally": true,
			"source":           "reckon",
			"description":      "blocked by reckon action " + p.IdempotencyKey,
		}
		res, err := client.CallTool(ctx, "add_ioc", args)
		if err != nil {
			// Ambiguous: the call may or may not have taken effect.
			return unknownResult(value, p.IdempotencyKey, err.Error()), nil
		}
		if res.IsError {
			return failResult(value, p.IdempotencyKey, action.WriteFatal, res.Text()), nil
		}
		return okResult(value, p.IdempotencyKey), nil

	case "remove_iocs":
		// Step 1: find the IOC ids for this value.
		search, err := client.CallTool(ctx, "search_iocs", map[string]any{
			"filter": "value:'" + value + "'",
		})
		if err != nil {
			return unknownResult(value, p.IdempotencyKey, "search_iocs: "+err.Error()), nil
		}
		if search.IsError {
			return failResult(value, p.IdempotencyKey, action.WriteRetryable, "search_iocs: "+search.Text()), nil
		}
		ids := iocIDs(search.StructuredOrText())
		if len(ids) == 0 {
			// Nothing to remove: the desired end state (no custom IOC for this
			// value) already holds. Honest success, not an error.
			return okResult(value, p.IdempotencyKey), nil
		}
		res, err := client.CallTool(ctx, "remove_iocs", map[string]any{"ids": ids})
		if err != nil {
			return unknownResult(value, p.IdempotencyKey, err.Error()), nil
		}
		if res.IsError {
			return failResult(value, p.IdempotencyKey, action.WriteFatal, res.Text()), nil
		}
		return okResult(value, p.IdempotencyKey), nil

	default:
		return nil, classErr(-32602, "unknown write operation "+p.Operation, string(action.WriteFatal))
	}
}

// okResult / failResult / unknownResult build the honest per-target
// WriteResults (08 §6c: a transport-ambiguous call is UNKNOWN, never an
// inferred success).
func okResult(target, key string) action.WriteResult {
	return action.WriteResult{
		FinalOutcome:     action.OutcomeSucceeded,
		PerTargetResults: map[string]action.PerTargetResult{target: action.TargetOK},
		AdapterRequestID: key,
		AuditDepth:       action.AuditFull,
	}
}

func failResult(target, key string, class action.WriteErrorClass, detail string) action.WriteResult {
	return action.WriteResult{
		FinalOutcome:     action.OutcomeFailed,
		PerTargetResults: map[string]action.PerTargetResult{target: action.TargetFail},
		AdapterRequestID: key,
		ErrorClass:       class,
		ErrorDetail:      detail,
		AuditDepth:       action.AuditFull,
	}
}

func unknownResult(target, key, detail string) action.WriteResult {
	return action.WriteResult{
		FinalOutcome:     action.OutcomeFailed,
		PerTargetResults: map[string]action.PerTargetResult{target: action.TargetUnknown},
		AdapterRequestID: key,
		ErrorClass:       action.WriteRetryable,
		ErrorDetail:      detail,
		AuditDepth:       action.AuditFull,
	}
}

// inferIOCType classifies an indicator value into Falcon's IOC types
// (domain/ipv4/ipv6/md5/sha256).
func inferIOCType(v string) string {
	v = strings.TrimSpace(v)
	switch {
	case isHex(v, 64):
		return "sha256"
	case isHex(v, 32):
		return "md5"
	case strings.Count(v, ":") >= 2:
		return "ipv6"
	case isIPv4(v):
		return "ipv4"
	case strings.Contains(v, "."):
		return "domain"
	default:
		return ""
	}
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// iocIDs extracts IOC ids from a search_iocs result (the Falcon API returns
// matches under resources[], as ids or as objects with an id).
func iocIDs(text string) []any {
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		return nil
	}
	raw, ok := obj["resources"].([]any)
	if !ok {
		return nil
	}
	out := make([]any, 0, len(raw))
	for _, r := range raw {
		switch v := r.(type) {
		case string:
			out = append(out, v)
		case map[string]any:
			if id, ok := v["id"].(string); ok && id != "" {
				out = append(out, id)
			}
		}
	}
	return out
}

type healthResult struct {
	Healthy bool   `json:"healthy"`
	Message string `json:"message"`
}

// health reports readiness (lazy spawn: configured-not-yet-connected is
// healthy).
func (b *bridge) health(_ context.Context) healthResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready {
		return healthResult{Healthy: false, Message: "not configured"}
	}
	if b.client == nil {
		return healthResult{Healthy: true, Message: "configured; falcon-mcp not yet connected"}
	}
	return healthResult{Healthy: true, Message: "falcon-mcp connected: " + b.client.ServerInfo().Name}
}

// invokeResult is the reckon-plugin invoke result wire shape.
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

// resolvedTarget extracts the frozen target identifier the engine resolved at
// request time (08 §4 — the adapter never re-resolves).
func resolvedTarget(params map[string]any) string {
	for _, k := range []string{"resolved_identifier", "value", "indicator"} {
		if v, ok := params[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
