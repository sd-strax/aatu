package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"
)

// TestMain re-execs this test binary as a mock MCP server when GO_MCP_MOCK is
// set (the standard os/exec test-helper pattern), so the client tests spawn a
// real child process speaking MCP over stdio.
func TestMain(m *testing.M) {
	if os.Getenv("GO_MCP_MOCK") == "1" {
		runMockMCPServer()
		return
	}
	os.Exit(m.Run())
}

func silent() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func spawnMock(t *testing.T) *Client {
	t.Helper()
	c, err := Spawn(context.Background(), []string{os.Args[0]},
		WithEnv(append(os.Environ(), "GO_MCP_MOCK=1")),
		WithLogger(silent()))
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestInitializeAndListTools(t *testing.T) {
	c := spawnMock(t)
	if si := c.ServerInfo(); si.Name != "mock-okta" {
		t.Fatalf("server info = %+v, want mock-okta", si)
	}
	tools, err := c.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 2 || tools[0].Name != "list_users" {
		t.Fatalf("tools = %+v, want [list_users deactivate_user]", tools)
	}
}

func TestCallToolReturnsText(t *testing.T) {
	c := spawnMock(t)
	res, err := c.CallTool(context.Background(), "list_users", nil)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatal("unexpected tool error")
	}
	if got := res.Text(); got != `[{"id":"u1"}]` {
		t.Fatalf("text = %q", got)
	}
}

// TestElicitationAutoAccepted: the mock's deactivate_user sends an
// elicitation/create and only returns success after the client accepts it. A
// hang here would mean the auto-accept handler didn't fire (the headless-bridge
// deadlock the handler exists to prevent).
func TestElicitationAutoAccepted(t *testing.T) {
	c := spawnMock(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := c.CallTool(ctx, "deactivate_user", map[string]any{"user_id": "u1"})
	if err != nil {
		t.Fatalf("CallTool deactivate_user: %v", err)
	}
	if res.IsError || res.Text() != `{"deactivated":true}` {
		t.Fatalf("result = %+v", res)
	}
}

// --- mock MCP server (child process) ---

func runMockMCPServer() {
	r := bufio.NewReader(os.Stdin)
	w := os.Stdout
	for {
		payload, err := readMessage(r)
		if err != nil {
			return
		}
		var msg message
		if err := json.Unmarshal(payload, &msg); err != nil {
			continue
		}
		switch msg.Method {
		case "initialize":
			reply(w, msg.ID, map[string]any{
				"protocolVersion": "2025-06-18",
				"serverInfo":      map[string]any{"name": "mock-okta", "version": "0.0.1"},
				"capabilities":    map[string]any{},
			})
		case "notifications/initialized":
			// notification, no reply
		case "tools/list":
			reply(w, msg.ID, map[string]any{"tools": []any{
				map[string]any{"name": "list_users", "description": "List users", "inputSchema": map[string]any{"type": "object"}},
				map[string]any{"name": "deactivate_user", "description": "Deactivate a user", "inputSchema": map[string]any{"type": "object"}},
			}})
		case "tools/call":
			var p struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(msg.Params, &p)
			if p.Name == "deactivate_user" {
				// Elicit confirmation, then wait for the client's accept before
				// returning success.
				eid := json.RawMessage("9001")
				elicitParams, _ := json.Marshal(map[string]any{
					"message": "Confirm deactivation?",
					"requestedSchema": map[string]any{
						"type":       "object",
						"properties": map[string]any{"confirm": map[string]any{"type": "boolean"}},
					},
				})
				writeRaw(w, &message{JSONRPC: "2.0", ID: &eid, Method: "elicitation/create", Params: elicitParams})
				if _, err := readMessage(r); err != nil { // the accept response
					return
				}
				reply(w, msg.ID, map[string]any{
					"content": []any{map[string]any{"type": "text", "text": `{"deactivated":true}`}},
					"isError": false,
				})
			} else {
				reply(w, msg.ID, map[string]any{
					"content": []any{map[string]any{"type": "text", "text": `[{"id":"u1"}]`}},
					"isError": false,
				})
			}
		}
	}
}

func reply(w io.Writer, id *json.RawMessage, result any) {
	raw, _ := json.Marshal(result)
	writeRaw(w, &message{JSONRPC: "2.0", ID: id, Result: raw})
}

func writeRaw(w io.Writer, msg *message) {
	payload, _ := json.Marshal(msg)
	_ = writeMessage(w, payload)
}
