package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
	"github.com/sd-strax/reckon/internal/mcpclient"
)

const version = "0.1.0"

// defaultServerCommand runs the greynoise-mcp-server that `reckon adapter setup
// greynoise` provisioned into the adapter's isolated venv (path relative to the
// install dir the host spawns the bridge in — deterministic, offline). Override
// with the `server_command` config field.
//
// NOTE (validate live, 11 §3 handshake-for-truth): the venv console-script name
// is the vendor's; confirm with `reckon adapter mcp-probe greynoise` and correct
// here + in the manifest entrypoint if it differs.
var defaultServerCommand = []string{"./.venv/bin/greynoise-mcp-server"}

// bridge holds the instance config and the lazily-spawned MCP client to
// greynoise-mcp-server. Read-only: no dispatch path.
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

// handle dispatches one reckon plugin protocol method. dispatch is absent:
// GreyNoise serves no action types, so a dispatch request is a config error.
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
	case "health":
		return b.health(ctx), nil
	default:
		return nil, &wireError{Code: -32601, Message: "unknown method " + method + " (greynoise is read-only)"}
	}
}

// configure validates + stores the instance config (11 §4.3). The api_key is an
// x-secret field the host has already resolved to plaintext before delivering it
// here (host.go → secretref.ResolveConfig); the bridge forwards it as the MCP
// server's environment and never logs it. No MCP server is spawned here (lazy).
func (b *bridge) configure(params []byte) (any, *wireError) {
	var p adapterplugin.ConfigureParams
	if err := jsonUnmarshal(params, &p); err != nil {
		return nil, &wireError{Code: -32602, Message: "configure params: " + err.Error()}
	}
	apiKey, _ := p.Config["api_key"].(string)
	if apiKey == "" {
		return nil, &wireError{Code: -32602, Message: "configure requires api_key (an x-secret reference resolved by the host)"}
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.serverCmd = defaultServerCommand
	if cmd := stringSlice(p.Config["server_command"]); len(cmd) > 0 {
		b.serverCmd = cmd
	}
	// The MCP server inherits PATH/HOME (so the provisioned venv/python resolve)
	// plus the GreyNoise API key. NOTE (validate live): the env var name is the
	// vendor server's; confirm via mcp-probe.
	b.env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"GREYNOISE_API_KEY=" + apiKey,
	}
	b.ready = true
	return map[string]any{"ok": true}, nil
}

// ensureClient lazily spawns + connects the greynoise-mcp-server MCP client.
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

// invoke runs a read operation: call the mapped GreyNoise tool, normalize the
// IP-reputation output to OCSF.
func (b *bridge) invoke(ctx context.Context, params []byte) (any, *wireError) {
	var p adapterplugin.InvokeParams
	if err := jsonUnmarshal(params, &p); err != nil {
		return nil, classErr(-32602, "invoke params: "+err.Error(), string(capability.ErrFallthrough))
	}
	client, err := b.ensureClient(ctx)
	if err != nil {
		return nil, classErr(-32000, "greynoise-mcp connect: "+err.Error(), string(capability.ErrUnhealthy))
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
		return nil, classErr(-32000, "greynoise tool "+tool+": "+res.Text(), string(capability.ErrFallthrough))
	}
	events, err := normalize(p.Operation, res.Text())
	if err != nil {
		return nil, classErr(-32000, "normalize "+tool+": "+err.Error(), string(capability.ErrFallthrough))
	}
	return invokeResult{SourceTool: "greynoise:" + tool, Events: events}, nil
}

type healthResult struct {
	Healthy bool   `json:"healthy"`
	Message string `json:"message"`
}

// health reports readiness. Lazy spawn: "configured, awaiting first use" is
// honest and healthy; once spawned, a dead client is unhealthy.
func (b *bridge) health(_ context.Context) healthResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready {
		return healthResult{Healthy: false, Message: "not configured"}
	}
	if b.client == nil {
		return healthResult{Healthy: true, Message: "configured; greynoise-mcp not yet connected"}
	}
	return healthResult{Healthy: true, Message: "greynoise-mcp connected: " + b.client.ServerInfo().Name}
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
