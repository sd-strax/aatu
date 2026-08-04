// Package mcpclient is a minimal Model Context Protocol (MCP) client: it spawns
// an MCP server as a child process and speaks JSON-RPC 2.0 over the server's
// stdio, doing the initialize handshake and tools/list + tools/call. It is the
// vendor-facing half of an MCP-class reckon adapter (design/11 §1.1): the reckon
// bridge holds one of these to a vendor's MCP server (okta-mcp-server,
// greynoise, falcon-mcp) while presenting the reckon plugin protocol to the
// engine.
//
// MCP's stdio transport is NEWLINE-DELIMITED JSON — one JSON-RPC message per
// line, no embedded newlines, UTF-8 (MCP spec, "stdio transport"). This is
// deliberately different from the reckon plugin protocol's Content-Length
// framing (internal/adapterplugin), because they are two different wire
// protocols that happen to both ride stdio; a bridge process speaks reckon
// framing on one fd pair and MCP framing on the other.
package mcpclient

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// maxLineBytes bounds one framed message. A tools/list or a tools/call result
// (a page of Okta users, already bounded by the vendor's paging) rides inside
// this; a line beyond it is a protocol error, not a legitimate payload.
const maxLineBytes = 32 << 20

// readMessage reads one newline-delimited JSON-RPC message. A bare "\n" (blank
// line) is skipped, so a server that pads with blank lines does not desync the
// reader. io.EOF is returned verbatim as the clean-shutdown signal.
func readMessage(r *bufio.Reader) ([]byte, error) {
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			if len(line) == 0 || errors.Is(err, io.EOF) {
				if len(trimNewline(line)) == 0 {
					return nil, err
				}
				// A final line with data but no trailing newline (server exiting).
				return trimNewline(line), nil
			}
			return nil, err
		}
		if len(line) > maxLineBytes {
			return nil, fmt.Errorf("mcpclient: message of %d bytes exceeds the %d-byte bound", len(line), maxLineBytes)
		}
		if msg := trimNewline(line); len(msg) > 0 {
			return msg, nil
		}
		// blank line: keep reading
	}
}

// writeMessage writes one newline-delimited JSON-RPC message. The caller
// serializes concurrent writers.
func writeMessage(w io.Writer, payload []byte) error {
	if _, err := w.Write(payload); err != nil {
		return err
	}
	_, err := w.Write([]byte{'\n'})
	return err
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
