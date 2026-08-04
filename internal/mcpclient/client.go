package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
)

// mcpProtocolVersion is the MCP revision this client negotiates. The server
// echoes a (possibly older) version it supports; we accept whatever it returns.
const mcpProtocolVersion = "2025-06-18"

// Tool is one MCP tool as reported by tools/list.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ContentBlock is one block of a tools/call result. v0 consumes text blocks
// (the vendor's JSON payload arrives as text); other block types are carried
// verbatim for the bridge to handle.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ToolResult is the result of tools/call. IsError marks a tool-level failure
// (the call completed but the tool reported an error), distinct from a transport
// error which surfaces as a Go error from CallTool.
type ToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError"`
}

// Text concatenates the text content blocks — the common case, where a tool
// returns one JSON document as text.
func (r ToolResult) Text() string {
	var b strings.Builder
	for _, c := range r.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	return b.String()
}

// ServerInfo identifies the MCP server from the initialize handshake.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Client is a live connection to one MCP server subprocess.
type Client struct {
	cmd        *exec.Cmd
	conn       *conn
	stdin      io.Closer
	done       chan struct{}
	lifeCancel context.CancelFunc
	logger     *slog.Logger

	serverInfo ServerInfo

	closeOnce sync.Once
}

// Option configures a Client at spawn.
type Option func(*options)

type options struct {
	env        []string
	logger     *slog.Logger
	onStderr   func(line string)
	elicit     func(ctx context.Context, params json.RawMessage) (any, error)
	clientName string
}

// WithEnv sets the child's environment (the vendor MCP server is configured via
// env — e.g. OKTA_ORG_URL/OKTA_CLIENT_ID/OKTA_SCOPES). Unlike a reckon adapter,
// an MCP server legitimately reads its config from env; keep secrets out of it
// where the flow allows (device grant needs no secret).
func WithEnv(env []string) Option { return func(o *options) { o.env = env } }

// WithLogger sets the logger for lifecycle events.
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.logger = l } }

// WithStderr sets a callback for each of the server's stderr lines. The device
// authorization URL + code that okta-mcp-server prints on first login arrive
// here — a probe routes them to the terminal so a human can complete the login.
func WithStderr(fn func(line string)) Option { return func(o *options) { o.onStderr = fn } }

// WithElicitationHandler overrides the default auto-accept elicitation handler
// (§ MCP elicitation). The default accepts every elicitation, because a reckon
// action reaching dispatch has already passed Gate 2 — the human approval — so a
// second confirmation at the vendor layer would be redundant and would deadlock
// a headless bridge.
func WithElicitationHandler(fn func(ctx context.Context, params json.RawMessage) (any, error)) Option {
	return func(o *options) { o.elicit = fn }
}

// Spawn launches an MCP server (argv), wires its stdio, runs the initialize
// handshake, and returns a ready Client. argv[0] is the executable (e.g.
// "uvx"), the rest its args (e.g. "okta-mcp-server").
func Spawn(ctx context.Context, argv []string, opts ...Option) (*Client, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("mcpclient: empty argv")
	}
	o := &options{logger: slog.Default(), clientName: "reckon-mcpclient"}
	for _, opt := range opts {
		opt(o)
	}
	if o.elicit == nil {
		o.elicit = autoAcceptElicitation
	}

	lifeCtx, lifeCancel := context.WithCancel(context.Background())
	// Spawning a caller-specified MCP server executable is the whole purpose of
	// this client (the bridge/probe names the vendor server, e.g. `uvx
	// okta-mcp-server`); the argv is operator-supplied config, not untrusted
	// input, exactly like the plugin host's manifest exec.
	cmd := exec.CommandContext(lifeCtx, argv[0], argv[1:]...)
	if o.env != nil {
		cmd.Env = o.env
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		lifeCancel()
		return nil, fmt.Errorf("mcpclient: stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		lifeCancel()
		return nil, fmt.Errorf("mcpclient: stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		lifeCancel()
		return nil, fmt.Errorf("mcpclient: stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		lifeCancel()
		return nil, fmt.Errorf("mcpclient: start %q: %w", argv[0], err)
	}

	go forwardStderr(stderr, o)

	c := &Client{
		cmd:        cmd,
		stdin:      stdin,
		done:       make(chan struct{}),
		lifeCancel: lifeCancel,
		logger:     o.logger,
	}
	c.conn = newConn(stdin, map[string]serverHandler{"elicitation/create": o.elicit})
	go func() {
		defer close(c.done)
		if err := c.conn.run(lifeCtx, stdout); err != nil {
			o.logger.Warn("mcp connection ended", "server", argv[0], "err", err)
		}
	}()

	if err := c.initialize(ctx, o.clientName); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// initialize runs the MCP handshake: initialize request, then the
// notifications/initialized notification.
func (c *Client) initialize(ctx context.Context, clientName string) error {
	params := map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{"elicitation": map[string]any{}},
		"clientInfo":      map[string]any{"name": clientName, "version": "0.1.0"},
	}
	var res struct {
		ProtocolVersion string     `json:"protocolVersion"`
		ServerInfo      ServerInfo `json:"serverInfo"`
	}
	if err := c.conn.Call(ctx, "initialize", params, &res); err != nil {
		return fmt.Errorf("mcpclient: initialize: %w", err)
	}
	c.serverInfo = res.ServerInfo
	if err := c.conn.Notify("notifications/initialized", nil); err != nil {
		return fmt.Errorf("mcpclient: initialized notification: %w", err)
	}
	c.logger.Info("mcp server ready", "server", res.ServerInfo.Name, "version", res.ServerInfo.Version, "protocol", res.ProtocolVersion)
	return nil
}

// ServerInfo returns the connected server's identity.
func (c *Client) ServerInfo() ServerInfo { return c.serverInfo }

// ListTools returns the server's tools (tools/list), following pagination.
func (c *Client) ListTools(ctx context.Context) ([]Tool, error) {
	var all []Tool
	cursor := ""
	for {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		var res struct {
			Tools      []Tool `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if err := c.conn.Call(ctx, "tools/list", params, &res); err != nil {
			return nil, fmt.Errorf("mcpclient: tools/list: %w", err)
		}
		all = append(all, res.Tools...)
		if res.NextCursor == "" {
			return all, nil
		}
		cursor = res.NextCursor
	}
}

// CallTool invokes a tool (tools/call). A transport/protocol failure returns a
// Go error; a tool-level failure returns a ToolResult with IsError = true.
func (c *Client) CallTool(ctx context.Context, name string, arguments map[string]any) (ToolResult, error) {
	if arguments == nil {
		arguments = map[string]any{}
	}
	params := map[string]any{"name": name, "arguments": arguments}
	var res ToolResult
	if err := c.conn.Call(ctx, "tools/call", params, &res); err != nil {
		return ToolResult{}, fmt.Errorf("mcpclient: tools/call %s: %w", name, err)
	}
	return res, nil
}

// Close terminates the server process. Safe to call more than once.
func (c *Client) Close() {
	c.closeOnce.Do(func() {
		if c.stdin != nil {
			_ = c.stdin.Close()
		}
		c.lifeCancel()
		if c.cmd != nil {
			_ = c.cmd.Wait()
		}
	})
}

// autoAcceptElicitation answers an MCP elicitation/create by accepting it (§ the
// reckon-gated-upstream rationale on WithElicitationHandler). It fills any
// boolean fields in the requested schema with true (a confirmation prompt), and
// otherwise returns an empty accepted content.
func autoAcceptElicitation(_ context.Context, params json.RawMessage) (any, error) {
	var p struct {
		RequestedSchema struct {
			Properties map[string]struct {
				Type string `json:"type"`
			} `json:"properties"`
		} `json:"requestedSchema"`
	}
	content := map[string]any{}
	if err := json.Unmarshal(params, &p); err == nil {
		for name, prop := range p.RequestedSchema.Properties {
			if prop.Type == "boolean" {
				content[name] = true
			}
		}
	}
	return map[string]any{"action": "accept", "content": content}, nil
}

func forwardStderr(r io.Reader, o *options) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if o.onStderr != nil {
			o.onStderr(line)
		} else {
			o.logger.Debug("mcp server stderr", "line", line)
		}
	}
}
