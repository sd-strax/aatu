package sidecar

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// JSON-RPC 2.0 error codes (the standard set plus LSP's cancelled).
const (
	codeParseError     = -32700
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	codeCancelled      = -32800 // LSP RequestCancelled — a turn aborted by `cancel`
)

// rpcErr is a coded JSON-RPC error a handler can return to control the wire
// code; any other error becomes codeInternal.
type rpcErr struct {
	Code    int
	Message string
}

func (e *rpcErr) Error() string { return e.Message }

func errInvalidParams(format string, args ...any) error {
	return &rpcErr{Code: codeInvalidParams, Message: fmt.Sprintf(format, args...)}
}

// wireError is the JSON-RPC error object.
type wireError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
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

// handler serves one method. The returned value is marshaled as the result;
// a *rpcErr controls the error code, any other error maps to codeInternal.
type handler func(ctx context.Context, params json.RawMessage) (any, error)

// conn is a minimal bidirectional JSON-RPC 2.0 connection over framed streams.
// Incoming requests dispatch on their own goroutines (a long-running `turn`
// must not block `cancel`); outgoing calls (the getToken callback) correlate
// responses by id. Writes are serialized by wmu.
type conn struct {
	handlers map[string]handler
	// onShutdown, when set, runs after the response to the "shutdown" method
	// has been written — the clean-exit seam (the response must flush before
	// the process stops serving).
	onShutdown func()

	wmu sync.Mutex
	w   io.Writer

	// wg tracks in-flight dispatch goroutines so a clean EOF can wait for
	// their responses to flush before the process exits (a client may send its
	// last request and half-close the pipe).
	wg sync.WaitGroup

	pmu     sync.Mutex
	nextID  int64
	pending map[int64]chan *message
}

func newConn(w io.Writer, handlers map[string]handler) *conn {
	return &conn{
		handlers: handlers,
		w:        w,
		pending:  map[int64]chan *message{},
	}
}

// dispatchGrace is how long a clean EOF waits for in-flight handlers to
// finish (and their responses to flush) before giving up on them. Pending
// outgoing calls are failed first, so a handler wedged on getToken from a
// gone client unblocks well inside this.
const dispatchGrace = 10 * time.Second

// runOn reads frames from r until EOF or error, dispatching as it goes. It
// returns nil on clean EOF (the client closed stdin — the normal shutdown)
// after waiting up to dispatchGrace for in-flight handlers, so a request
// followed by half-close still gets its response. On a read error or ctx
// cancel, in-flight goroutines are abandoned (the process is exiting).
func (c *conn) runOn(ctx context.Context, r io.Reader) error {
	br := bufio.NewReader(r)
	for {
		payload, err := readFrame(br)
		if err != nil {
			c.failPending(err)
			if errors.Is(err, io.EOF) {
				c.waitDispatches(ctx)
				return nil
			}
			return err
		}
		var msg message
		if err := json.Unmarshal(payload, &msg); err != nil {
			// A parse failure has no usable id to respond to; report and continue.
			_ = c.writeMsg(&message{JSONRPC: "2.0", Error: &wireError{Code: codeParseError, Message: err.Error()}})
			continue
		}
		switch {
		case msg.Method != "": // request or notification
			c.wg.Add(1)
			go func(m *message) {
				defer c.wg.Done()
				c.dispatch(ctx, m)
			}(&msg)
		case msg.ID != nil: // response to one of our calls
			c.settle(&msg)
		}
	}
}

// waitDispatches blocks until in-flight handlers finish, ctx cancels, or the
// grace expires.
func (c *conn) waitDispatches(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	case <-time.After(dispatchGrace):
	}
}

// dispatch runs one incoming request/notification handler and writes the
// response (requests only).
func (c *conn) dispatch(ctx context.Context, msg *message) {
	h, ok := c.handlers[msg.Method]
	if !ok {
		if msg.ID != nil {
			c.respondErr(msg.ID, &rpcErr{Code: codeMethodNotFound, Message: fmt.Sprintf("unknown method %q", msg.Method)})
		}
		return
	}
	result, err := h(ctx, msg.Params)
	if msg.ID == nil {
		return // notification: nothing to write
	}
	if err != nil {
		var coded *rpcErr
		if !errors.As(err, &coded) {
			coded = &rpcErr{Code: codeInternal, Message: err.Error()}
		}
		c.respondErr(msg.ID, coded)
	} else {
		raw, merr := json.Marshal(result)
		if merr != nil {
			c.respondErr(msg.ID, &rpcErr{Code: codeInternal, Message: "marshal result: " + merr.Error()})
			return
		}
		// A failed write means the pipe is gone; the read loop is about to end
		// the connection, so there is nowhere to surface it.
		_ = c.writeMsg(&message{JSONRPC: "2.0", ID: msg.ID, Result: raw})
	}
	if msg.Method == "shutdown" && c.onShutdown != nil {
		c.onShutdown() // after the response is on the wire
	}
}

// Call issues an outgoing request and decodes its result into out (may be nil).
func (c *conn) Call(ctx context.Context, method string, params, out any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("sidecar: marshal %s params: %w", method, err)
	}
	c.pmu.Lock()
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
			return fmt.Errorf("sidecar: connection closed awaiting %s response", method)
		}
		if resp.Error != nil {
			return fmt.Errorf("sidecar: %s: %s (code %d)", method, resp.Error.Message, resp.Error.Code)
		}
		if out != nil {
			if err := json.Unmarshal(resp.Result, out); err != nil {
				return fmt.Errorf("sidecar: decode %s result: %w", method, err)
			}
		}
		return nil
	}
}

// Notify sends a fire-and-forget notification (no id, no response).
func (c *conn) Notify(method string, params any) {
	raw, err := json.Marshal(params)
	if err != nil {
		return
	}
	_ = c.writeMsg(&message{JSONRPC: "2.0", Method: method, Params: raw})
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

// failPending closes every waiting Call when the read loop ends, so a token
// request in flight fails fast instead of hanging its turn forever.
func (c *conn) failPending(error) {
	c.pmu.Lock()
	defer c.pmu.Unlock()
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
}

func (c *conn) respondErr(id *json.RawMessage, e *rpcErr) {
	_ = c.writeMsg(&message{JSONRPC: "2.0", ID: id, Error: &wireError{Code: e.Code, Message: e.Message}})
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
