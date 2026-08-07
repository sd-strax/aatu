// Command reckon-adapter-crowdstrike-response is a NATIVE_API-class reckon
// adapter (design/11; implementation/adapter-candidates.md §3, Adapter B) — the
// deliberately tiny write-only sibling of reckon-adapter-crowdstrike-falcon,
// doing the one thing the vendor MCP preview does not reliably expose: per-host
// network containment (PerformActionV2 contain / lift_containment). It is the
// first native-class adapter: a static Go binary, no runtime block, no child
// process — the reckon plugin protocol on stdin/stdout and a hand-rolled
// OAuth2+HTTPS client to the Falcon API. Together the pair is the
// two-adapters-one-vendor split 11 §8 sanctions: MCP where it is clean, native
// where it is not.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "reckon-adapter-crowdstrike-response:", err)
		os.Exit(1)
	}
}

func run() error {
	b := newBridge()
	defer b.Close()
	srv := &server{out: os.Stdout, bridge: b}
	if err := srv.serve(os.Stdin); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// --- reckon plugin protocol (adapter side) ---

type message struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *wireError       `json:"error,omitempty"`
}

type wireError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// server reads Content-Length-framed JSON-RPC from the engine and dispatches to
// the bridge. One request at a time (the adapter declares concurrency 1).
type server struct {
	out    io.Writer
	bridge *bridge
}

func (s *server) serve(r io.Reader) error {
	br := bufio.NewReader(r)
	for {
		payload, err := readFrame(br)
		if err != nil {
			return err
		}
		var msg message
		if err := json.Unmarshal(payload, &msg); err != nil {
			continue
		}
		if msg.Method == "" || msg.ID == nil {
			continue // the engine only sends requests
		}
		result, rerr := s.bridge.handle(context.Background(), msg.Method, msg.Params)
		if rerr != nil {
			s.write(message{ID: msg.ID, Error: rerr})
			continue
		}
		raw, err := json.Marshal(result)
		if err != nil {
			s.write(message{ID: msg.ID, Error: &wireError{Code: -32603, Message: "marshal result: " + err.Error()}})
			continue
		}
		s.write(message{ID: msg.ID, Result: raw})
	}
}

func (s *server) write(msg message) {
	msg.JSONRPC = "2.0"
	payload, err := json.Marshal(msg)
	if err != nil {
		return
	}
	if _, err := fmt.Fprintf(s.out, "Content-Length: %d\r\n\r\n", len(payload)); err != nil {
		return
	}
	_, _ = s.out.Write(payload)
}

// readFrame reads one Content-Length framed message (11 §2).
func readFrame(r *bufio.Reader) ([]byte, error) {
	length := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return nil, fmt.Errorf("bad Content-Length %q", value)
			}
			length = n
		}
	}
	if length < 0 {
		return nil, fmt.Errorf("frame missing Content-Length")
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(r, payload)
	return payload, err
}

// classErr builds a reckon-taxonomy error (data.class) for invoke failures
// (03 §6.2).
func classErr(code int, msg, class string) *wireError {
	data, _ := json.Marshal(map[string]string{"class": class})
	return &wireError{Code: code, Message: msg, Data: data}
}
