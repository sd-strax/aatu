package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// JSON-RPC 2.0 error codes used by the client when answering a server request.
const (
	codeMethodNotFound = -32601
	codeInternalError  = -32603
)

type wireError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// message is the JSON-RPC 2.0 envelope.
type message struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *wireError       `json:"error,omitempty"`
}

// callError is a JSON-RPC error surfaced from a client Call (e.g. a tools/call
// that failed on the server).
type callError struct {
	Code    int
	Message string
}

func (e *callError) Error() string { return fmt.Sprintf("mcp rpc error %d: %s", e.Code, e.Message) }

// serverHandler answers a request the SERVER initiates toward the client (MCP is
// bidirectional: the server may send elicitation/create, roots/list, or
// sampling/createMessage). The returned value is marshaled as the result.
type serverHandler func(ctx context.Context, params json.RawMessage) (any, error)

// conn is the client side of a bidirectional JSON-RPC 2.0 connection to one MCP
// server over its stdin (writes) and stdout (reads), newline-framed. Client
// requests correlate responses by id; server-initiated requests dispatch to the
// registered handlers so an elicitation prompt is answered rather than hanging.
type conn struct {
	handlers map[string]serverHandler

	wmu sync.Mutex
	w   io.Writer

	pmu     sync.Mutex
	nextID  int64
	pending map[int64]chan *message
	closed  bool
}

func newConn(w io.Writer, handlers map[string]serverHandler) *conn {
	return &conn{handlers: handlers, w: w, pending: map[int64]chan *message{}}
}

// run reads frames from r (the server's stdout) until EOF/error, routing
// responses to waiting Calls and dispatching server-initiated requests to
// handlers. Returns nil on clean EOF.
func (c *conn) run(ctx context.Context, r io.Reader) error {
	br := bufio.NewReader(r)
	for {
		payload, err := readMessage(br)
		if err != nil {
			c.failPending(err)
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var msg message
		if err := json.Unmarshal(payload, &msg); err != nil {
			continue // unparseable line with no id to route
		}
		switch {
		case msg.Method != "" && msg.ID != nil:
			go c.dispatch(ctx, &msg) // server-initiated request
		case msg.Method != "":
			// server notification (e.g. notifications/message) — ignored in v0
		case msg.ID != nil:
			c.settle(&msg)
		}
	}
}

// dispatch answers a server-initiated request.
func (c *conn) dispatch(ctx context.Context, msg *message) {
	h, ok := c.handlers[msg.Method]
	if !ok {
		c.respondErr(msg.ID, codeMethodNotFound, "unsupported method "+msg.Method)
		return
	}
	result, err := h(ctx, msg.Params)
	if err != nil {
		c.respondErr(msg.ID, codeInternalError, err.Error())
		return
	}
	raw, err := json.Marshal(result)
	if err != nil {
		c.respondErr(msg.ID, codeInternalError, "marshal result: "+err.Error())
		return
	}
	_ = c.writeMsg(&message{JSONRPC: "2.0", ID: msg.ID, Result: raw})
}

// Call issues a client→server request and decodes its result into out (may be nil).
func (c *conn) Call(ctx context.Context, method string, params, out any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("mcpclient: marshal %s params: %w", method, err)
		}
		raw = b
	}
	c.pmu.Lock()
	if c.closed {
		c.pmu.Unlock()
		return fmt.Errorf("mcpclient: connection closed before %s", method)
	}
	c.nextID++
	id := c.nextID
	ch := make(chan *message, 1)
	c.pending[id] = ch
	c.pmu.Unlock()
	defer func() {
		c.pmu.Lock()
		delete(c.pending, id)
		c.pmu.Unlock()
	}()

	idRaw := json.RawMessage(fmt.Sprintf("%d", id))
	if err := c.writeMsg(&message{JSONRPC: "2.0", ID: &idRaw, Method: method, Params: raw}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resp, ok := <-ch:
		if !ok {
			return fmt.Errorf("mcpclient: connection closed awaiting %s response", method)
		}
		if resp.Error != nil {
			return &callError{Code: resp.Error.Code, Message: resp.Error.Message}
		}
		if out != nil && len(resp.Result) > 0 {
			if err := json.Unmarshal(resp.Result, out); err != nil {
				return fmt.Errorf("mcpclient: decode %s result: %w", method, err)
			}
		}
		return nil
	}
}

// Notify sends a client→server notification (no id, no response).
func (c *conn) Notify(method string, params any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	return c.writeMsg(&message{JSONRPC: "2.0", Method: method, Params: raw})
}

func (c *conn) settle(msg *message) {
	var id int64
	if err := json.Unmarshal(*msg.ID, &id); err != nil {
		return
	}
	c.pmu.Lock()
	ch, ok := c.pending[id]
	delete(c.pending, id)
	c.pmu.Unlock()
	if ok {
		ch <- msg
	}
}

func (c *conn) failPending(error) {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	c.closed = true
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
}

func (c *conn) respondErr(id *json.RawMessage, code int, msg string) {
	_ = c.writeMsg(&message{JSONRPC: "2.0", ID: id, Error: &wireError{Code: code, Message: msg}})
}

func (c *conn) writeMsg(msg *message) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return writeMessage(c.w, payload)
}
