package adapterplugin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// JSON-RPC 2.0 error codes (the standard set). An adapter returns these in the
// error object of a response; the host maps them onto the 03 §6.2 / 08 §5 error
// taxonomies in plugin.go.
const (
	codeParseError     = -32700
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
)

// wireError is the JSON-RPC error object.
type wireError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	// Data carries the reckon error class an adapter reports on a failed
	// invoke/dispatch (§4, mapping to 03 §6.2 / 08 §5). It is optional; a bare
	// error with no class is treated as the safe default by the host.
	Data json.RawMessage `json:"data,omitempty"`
}

// message is the JSON-RPC 2.0 envelope: a request (method+id), a notification
// (method, no id), or a response (id, result|error).
type message struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *wireError       `json:"error,omitempty"`
}

// callError is a JSON-RPC error surfaced from a Call. The host inspects Code and
// Data to classify the failure; Call itself stays transport-generic.
type callError struct {
	Code    int
	Message string
	Data    json.RawMessage
}

func (e *callError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// conn is the engine side of a JSON-RPC 2.0 connection to one adapter process,
// over the child's stdout (reads) and stdin (writes). The engine only ever
// *calls* an adapter in v0 (§2 "invoke/dispatch/health mapped 1:1"); the read
// loop therefore routes responses to waiting Calls and answers any unexpected
// adapter-initiated request with method-not-found rather than hanging it.
// Writes are serialized by wmu.
type conn struct {
	wmu sync.Mutex
	w   io.Writer

	pmu     sync.Mutex
	nextID  int64
	pending map[int64]chan *message
	closed  bool
}

func newConn(w io.Writer) *conn {
	return &conn{w: w, pending: map[int64]chan *message{}}
}

// runOn reads frames from r (the child's stdout) until EOF or error, routing
// responses. It returns nil on clean EOF (the adapter exited) and the read
// error otherwise; either way every waiting Call is failed so a caller blocked
// on a dead adapter unblocks immediately.
func (c *conn) runOn(r io.Reader) error {
	br := bufio.NewReader(r)
	for {
		payload, err := readFrame(br)
		if err != nil {
			c.failPending(err)
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var msg message
		if err := json.Unmarshal(payload, &msg); err != nil {
			continue // a frame we can't parse has no id to route; drop it
		}
		switch {
		case msg.Method != "" && msg.ID != nil:
			// An adapter-initiated request. v0 has none; answer cleanly so a
			// confused adapter gets an error instead of a wedged call.
			c.respondErr(msg.ID, codeMethodNotFound, fmt.Sprintf("unknown method %q", msg.Method))
		case msg.Method != "":
			// Adapter notification (e.g. a log line). Ignored in v0.
		case msg.ID != nil:
			c.settle(&msg)
		}
	}
}

// Call issues an outgoing request and decodes its result into out (may be nil).
// A JSON-RPC error response returns a *callError; a closed/gone connection
// returns a plain error.
func (c *conn) Call(ctx context.Context, method string, params, out any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("adapterplugin: marshal %s params: %w", method, err)
	}
	c.pmu.Lock()
	if c.closed {
		c.pmu.Unlock()
		return fmt.Errorf("adapterplugin: connection closed before %s", method)
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
			return fmt.Errorf("adapterplugin: connection closed awaiting %s response", method)
		}
		if resp.Error != nil {
			return &callError{Code: resp.Error.Code, Message: resp.Error.Message, Data: resp.Error.Data}
		}
		if out != nil && len(resp.Result) > 0 {
			if err := json.Unmarshal(resp.Result, out); err != nil {
				return fmt.Errorf("adapterplugin: decode %s result: %w", method, err)
			}
		}
		return nil
	}
}

// settle routes a response to its waiting Call.
func (c *conn) settle(msg *message) {
	var id int64
	if err := json.Unmarshal(*msg.ID, &id); err != nil {
		return // a response id we never issued (we only mint numbers)
	}
	c.pmu.Lock()
	ch, ok := c.pending[id]
	delete(c.pending, id)
	c.pmu.Unlock()
	if ok {
		ch <- msg
	}
}

// failPending closes every waiting Call when the read loop ends, so a handshake
// or invoke in flight against a dead adapter fails fast instead of hanging.
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
	return writeFrame(c.w, payload)
}
