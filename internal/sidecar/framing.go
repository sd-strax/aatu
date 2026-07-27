// Package sidecar is the workbench-facing agent-loop server: `reckon
// investigate --stdio` speaks JSON-RPC 2.0 over stdin/stdout using the
// LSP-style Content-Length framing (what vscode-jsonrpc emits), wrapping the
// canonical Go agent.Session. Decision record: implementation/agent-sidecar.md
// — one loop implementation, sidecar transport, token handoff via the
// getToken client callback (the extension owns auth; this process holds no
// refresh tokens and no passwords).
package sidecar

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// maxFrameBytes bounds one framed message. Tool results are clipped before
// they ride notifications, so a frame beyond this is a protocol error, not a
// legitimate payload.
const maxFrameBytes = 32 << 20

// readFrame reads one Content-Length framed message: any number of
// "Header: value\r\n" lines, a blank "\r\n", then exactly Content-Length bytes
// of payload. Unknown headers (vscode-jsonrpc sends Content-Type) are ignored.
func readFrame(r *bufio.Reader) ([]byte, error) {
	length := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err // io.EOF between frames is the clean-shutdown path
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break // end of headers
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("sidecar: malformed header line %q", line)
		}
		if strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return nil, fmt.Errorf("sidecar: bad Content-Length %q", strings.TrimSpace(value))
			}
			length = n
		}
	}
	if length < 0 {
		return nil, fmt.Errorf("sidecar: frame missing Content-Length")
	}
	if length > maxFrameBytes {
		return nil, fmt.Errorf("sidecar: frame of %d bytes exceeds the %d-byte bound", length, maxFrameBytes)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("sidecar: short frame body: %w", err)
	}
	return payload, nil
}

// writeFrame writes one Content-Length framed message. The caller serializes
// concurrent writers (conn holds the write mutex).
func writeFrame(w io.Writer, payload []byte) error {
	if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", len(payload)); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
