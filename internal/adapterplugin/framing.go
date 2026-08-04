// Package adapterplugin is the engine-side host for out-of-process adapters
// (design/11-adapter-plugins.md): one adapter = one executable, spawned and
// supervised by the backend, speaking JSON-RPC 2.0 over stdio. It is the
// sibling peer of internal/sidecar (the workbench↔engine agent channel) —
// same Content-Length framing and JSON-RPC plumbing, opposite role: here the
// engine is the parent that spawns and *calls*, and the adapter is the child
// that answers `initialize`/`describe`/`configure`/`invoke`/`dispatch`/`health`
// (§4). The framing is deliberately a mirror rather than a shared import so the
// working agent channel is never perturbed by adapter-transport changes; a
// later consolidation into a shared jsonrpc package is a pure refactor.
//
// This package owns the transport and process model (§2–§4) and the
// manifest/install layout (§3). The *semantic* contracts it carries are
// capability.Adapter (03 §5.3) and action.WriteAdapter (08 §5); the facades in
// facade.go adapt a live plugin onto those interfaces. Enablement (§5) and
// binding resolution (03 §3 / 08 §4) stay where they already live.
package adapterplugin

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// maxFrameBytes bounds one framed message. An adapter's `describe` (its whole
// self-description) and an `invoke` result (a page of OCSF events, already
// bounded by the vendor's own paging) both ride inside this; a frame beyond it
// is a protocol error, not a legitimate payload.
const maxFrameBytes = 32 << 20

// readFrame reads one Content-Length framed message: any number of
// "Header: value\r\n" lines, a blank "\r\n", then exactly Content-Length bytes
// of payload. Unknown headers are ignored (an adapter written against a generic
// JSON-RPC library may emit Content-Type).
func readFrame(r *bufio.Reader) ([]byte, error) {
	length := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err // io.EOF between frames is the clean-shutdown / crash path
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break // end of headers
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("adapterplugin: malformed header line %q", line)
		}
		if strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return nil, fmt.Errorf("adapterplugin: bad Content-Length %q", strings.TrimSpace(value))
			}
			length = n
		}
	}
	if length < 0 {
		return nil, fmt.Errorf("adapterplugin: frame missing Content-Length")
	}
	if length > maxFrameBytes {
		return nil, fmt.Errorf("adapterplugin: frame of %d bytes exceeds the %d-byte bound", length, maxFrameBytes)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("adapterplugin: short frame body: %w", err)
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
