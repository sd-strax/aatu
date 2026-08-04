package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
	"github.com/sd-strax/reckon/internal/mcpclient"
)

const version = "0.1.0"

// defaultServerCommand runs the okta-mcp-server that `reckon adapter setup`
// provisioned into the adapter's isolated venv. The path is relative to the
// bridge's working directory (its install dir, where the host spawns it), so it
// is deterministic and offline — no runtime package fetch, no dependency on the
// host's Python. Overridable via the `server_command` config field (e.g. a
// docker invocation, or `uvx --python 3.13 okta-mcp-server` for an unprovisioned
// dev run).
var defaultServerCommand = []string{"./.venv/bin/okta-mcp-server"}

// bridge holds the instance config and the lazily-spawned MCP client to
// okta-mcp-server. The client is spawned on first demand, not at configure:
// the first `uvx` run may download the package and the device-grant token check
// can be slow, which would blow the engine's handshake timeout.
type bridge struct {
	mu        sync.Mutex
	client    *mcpclient.Client
	serverCmd []string
	env       []string
	ready     bool // configure succeeded
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

// configure validates + stores the instance config (11 §4.3). It does NOT spawn
// the MCP server (that is lazy). Auth is the MCP server's job; the bridge only
// forwards the non-secret org/client/scopes as its environment. The device-grant
// token must be primed out of band (`reckon adapter mcp-probe`) so the lazy
// spawn finds a cached token and never blocks on an interactive login.
func (b *bridge) configure(params []byte) (any, *wireError) {
	var p adapterplugin.ConfigureParams
	if err := jsonUnmarshal(params, &p); err != nil {
		return nil, &wireError{Code: -32602, Message: "configure params: " + err.Error()}
	}
	orgURL, _ := p.Config["org_url"].(string)
	clientID, _ := p.Config["client_id"].(string)
	if orgURL == "" || clientID == "" {
		return nil, &wireError{Code: -32602, Message: "configure requires org_url and client_id"}
	}
	scopes, _ := p.Config["scopes"].(string)
	if scopes == "" {
		scopes = "okta.users.read okta.groups.read okta.logs.read okta.users.manage"
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.serverCmd = defaultServerCommand
	if cmd := stringSlice(p.Config["server_command"]); len(cmd) > 0 {
		b.serverCmd = cmd
	}
	// The MCP server inherits PATH/HOME (so uv/python resolve and the cached
	// device-grant token under HOME is found) plus its Okta config. No secret is
	// present on the device-grant path.
	b.env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"OKTA_ORG_URL=" + orgURL,
		"OKTA_CLIENT_ID=" + clientID,
		"OKTA_SCOPES=" + scopes,
	}
	b.ready = true
	return map[string]any{"ok": true}, nil
}

// ensureClient lazily spawns + connects the okta-mcp-server MCP client.
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

// invoke runs a read operation: call the mapped Okta tool, normalize to OCSF.
func (b *bridge) invoke(ctx context.Context, params []byte) (any, *wireError) {
	var p adapterplugin.InvokeParams
	if err := jsonUnmarshal(params, &p); err != nil {
		return nil, classErr(-32602, "invoke params: "+err.Error(), string(capability.ErrFallthrough))
	}
	client, err := b.ensureClient(ctx)
	if err != nil {
		return nil, classErr(-32000, "okta-mcp connect: "+err.Error(), string(capability.ErrUnhealthy))
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
		return nil, classErr(-32000, "okta tool "+tool+": "+res.Text(), string(capability.ErrFallthrough))
	}
	events, err := normalize(p.Operation, res.Text())
	if err != nil {
		return nil, classErr(-32000, "normalize "+tool+": "+err.Error(), string(capability.ErrFallthrough))
	}
	return invokeResult{SourceTool: "okta:" + tool, Events: events}, nil
}

// dispatch runs a write operation. account.disable → deactivate_user. There is
// no normalizer on the write path — the result is an outcome (08 §5).
func (b *bridge) dispatch(ctx context.Context, params []byte) (any, *wireError) {
	var p adapterplugin.DispatchParams
	if err := jsonUnmarshal(params, &p); err != nil {
		return nil, classErr(-32602, "dispatch params: "+err.Error(), string(action.WriteFatal))
	}
	if p.Operation != "deactivate_user" {
		return nil, classErr(-32602, "unknown write operation "+p.Operation, string(action.WriteFatal))
	}
	target := resolvedTarget(p.Params)
	if target == "" {
		return nil, classErr(-32602, "deactivate_user requires a resolved target (user id/login)", string(action.WriteFatal))
	}
	client, err := b.ensureClient(ctx)
	if err != nil {
		return nil, classErr(-32000, "okta-mcp connect: "+err.Error(), string(action.WriteFatal))
	}
	// The MCP server elicits a confirmation for deactivation; the client
	// auto-accepts (reckon Gate 2 already approved this dispatch).
	res, err := client.CallTool(ctx, "deactivate_user", map[string]any{"user_id": target})
	if err != nil {
		// Ambiguous: the call may or may not have taken effect — honest residual.
		return action.WriteResult{
			FinalOutcome:     action.OutcomeFailed,
			PerTargetResults: map[string]action.PerTargetResult{target: action.TargetUnknown},
			AdapterRequestID: p.IdempotencyKey,
			ErrorClass:       action.WriteRetryable,
			ErrorDetail:      err.Error(),
			AuditDepth:       action.AuditFull,
		}, nil
	}
	if res.IsError {
		return action.WriteResult{
			FinalOutcome:     action.OutcomeFailed,
			PerTargetResults: map[string]action.PerTargetResult{target: action.TargetFail},
			AdapterRequestID: p.IdempotencyKey,
			ErrorClass:       action.WriteFatal,
			ErrorDetail:      res.Text(),
			AuditDepth:       action.AuditFull,
		}, nil
	}
	return action.WriteResult{
		FinalOutcome:     action.OutcomeSucceeded,
		PerTargetResults: map[string]action.PerTargetResult{target: action.TargetOK},
		AdapterRequestID: p.IdempotencyKey,
		AuditDepth:       action.AuditFull,
	}, nil
}

type healthResult struct {
	Healthy bool   `json:"healthy"`
	Message string `json:"message"`
}

// health reports readiness. Before the first demand the client is not spawned;
// "configured, awaiting first use" is honest and healthy (lazy spawn). Once
// spawned, a dead client is unhealthy.
func (b *bridge) health(_ context.Context) healthResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready {
		return healthResult{Healthy: false, Message: "not configured"}
	}
	if b.client == nil {
		return healthResult{Healthy: true, Message: "configured; okta-mcp not yet connected"}
	}
	return healthResult{Healthy: true, Message: "okta-mcp connected: " + b.client.ServerInfo().Name}
}

// invokeResult is the reckon-plugin invoke result wire shape (matches the host's
// decoder in internal/adapterplugin).
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
