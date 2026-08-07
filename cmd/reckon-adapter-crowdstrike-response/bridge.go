package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
)

const version = "0.1.0"

// bridge holds the instance config and the native Falcon client. Write-only:
// invoke is rejected (this adapter observes nothing, it acts — the read
// surface lives on the sibling MCP adapter).
type bridge struct {
	mu     sync.Mutex
	client *falconClient
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
		return nil, classErr(-32602, "crowdstrike-response is write-only (reads live on crowdstrike-falcon)", string(capability.ErrFallthrough))
	default:
		return nil, &wireError{Code: -32601, Message: "unknown method " + method}
	}
}

// configure validates + stores the instance config (11 §4.3). client_secret is
// an x-secret field the host resolved to plaintext before delivery; it lives
// only in this process's memory, never in a child environment (there is no
// child — this adapter is the native client).
func (b *bridge) configure(params []byte) (any, *wireError) {
	var p adapterplugin.ConfigureParams
	if err := json.Unmarshal(params, &p); err != nil {
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
	b.client = newFalconClient(baseURL, clientID, clientSecret, memberCID)
	b.mu.Unlock()
	return map[string]any{"ok": true}, nil
}

const defaultBaseURL = "https://api.crowdstrike.com"

// dispatch performs contain / lift_containment for one target device
// (PerformActionV2). The engine resolved the target at request time (08 §4);
// resolved_identifier is the Falcon device id. Per-target honesty (08 §6c):
//   - device in resources[] → OK
//   - device absent + errors[] → FAIL with the vendor detail
//   - transport-level failure → UNKNOWN (the action may have taken effect)
func (b *bridge) dispatch(ctx context.Context, params []byte) (any, *wireError) {
	var p adapterplugin.DispatchParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, classErr(-32602, "dispatch params: "+err.Error(), string(action.WriteFatal))
	}
	var actionName string
	switch p.Operation {
	case "contain":
		actionName = "contain"
	case "lift_containment":
		actionName = "lift_containment"
	default:
		return nil, classErr(-32602, "unknown write operation "+p.Operation+" (contain | lift_containment)", string(action.WriteFatal))
	}
	deviceID := resolvedTarget(p.Params)
	if deviceID == "" {
		return nil, classErr(-32602, p.Operation+" requires a resolved target (the Falcon device id)", string(action.WriteFatal))
	}

	b.mu.Lock()
	client := b.client
	b.mu.Unlock()
	if client == nil {
		return nil, classErr(-32000, "adapter not configured", string(action.WriteFatal))
	}

	resp, status, err := client.deviceAction(ctx, actionName, []string{deviceID})
	if err != nil {
		// Transport-ambiguous: never infer either way.
		return action.WriteResult{
			FinalOutcome:     action.OutcomeFailed,
			PerTargetResults: map[string]action.PerTargetResult{deviceID: action.TargetUnknown},
			AdapterRequestID: p.IdempotencyKey,
			ErrorClass:       action.WriteRetryable,
			ErrorDetail:      err.Error(),
			AuditDepth:       action.AuditFull,
		}, nil
	}

	for _, r := range resp.Resources {
		if r.ID == deviceID {
			return action.WriteResult{
				FinalOutcome:     action.OutcomeSucceeded,
				PerTargetResults: map[string]action.PerTargetResult{deviceID: action.TargetOK},
				AdapterRequestID: p.IdempotencyKey,
				AuditDepth:       action.AuditFull,
			}, nil
		}
	}

	detail := fmt.Sprintf("device %s not in the action response (HTTP %d)", deviceID, status)
	errClass := action.WriteRetryable
	if len(resp.Errors) > 0 {
		detail = fmt.Sprintf("HTTP %d: %s (code %d)", status, resp.Errors[0].Message, resp.Errors[0].Code)
		// Auth/permission/not-found are not retryable; rate limiting is.
		if status != 429 && status < 500 {
			errClass = action.WriteFatal
		}
	}
	return action.WriteResult{
		FinalOutcome:     action.OutcomeFailed,
		PerTargetResults: map[string]action.PerTargetResult{deviceID: action.TargetFail},
		AdapterRequestID: p.IdempotencyKey,
		ErrorClass:       errClass,
		ErrorDetail:      detail,
		AuditDepth:       action.AuditFull,
	}, nil
}

type healthResult struct {
	Healthy bool   `json:"healthy"`
	Message string `json:"message"`
}

// health reports readiness: configured is healthy (the OAuth token is minted
// lazily at first dispatch; a bad credential surfaces there as a dispatch
// failure, and here on subsequent probes once a token attempt has failed).
func (b *bridge) health() healthResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.client == nil {
		return healthResult{Healthy: false, Message: "not configured"}
	}
	return healthResult{Healthy: true, Message: "configured (native Falcon client, " + b.client.baseURL + ")"}
}

// resolvedTarget extracts the frozen target identifier the engine resolved at
// request time (08 §4 — the adapter never re-resolves).
func resolvedTarget(params map[string]any) string {
	for _, k := range []string{"resolved_identifier", "device_id", "id"} {
		if v, ok := params[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
