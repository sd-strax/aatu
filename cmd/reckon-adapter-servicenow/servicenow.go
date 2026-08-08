package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// snowClient is a minimal native client for the ServiceNow Table API
// (/api/now/table/<table>). Deliberately hand-rolled (no SDK): the surface is a
// POST (create), a PATCH (update), and a GET (query) — a native adapter's whole
// point is a static binary that vendors nothing (12 §2). Auth is Basic
// (username/password); the password arrives already resolved to plaintext by
// the host (11 §4.3) and lives only in this process's memory.
type snowClient struct {
	baseURL  string
	username string
	password string
	table    string
	httpc    *http.Client
}

func newSnowClient(instanceURL, username, password, table string) *snowClient {
	if table == "" {
		table = "incident"
	}
	return &snowClient{
		baseURL:  strings.TrimRight(instanceURL, "/"),
		username: username,
		password: password,
		table:    table,
		httpc:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *snowClient) authHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.username+":"+c.password))
}

// snowRecord is the subset of a Table API record this adapter reads back. The
// Table API returns every field as a string (or a {value, display_value}
// reference object when sysparm_display_value is set — we never set it, so
// these stay plain strings).
type snowRecord struct {
	SysID  string `json:"sys_id"`
	Number string `json:"number"`
	State  string `json:"state"`
}

// snowError is the Table API failure envelope: {"error":{"message","detail"},
// "status":"failure"}.
type snowError struct {
	Error struct {
		Message string `json:"message"`
		Detail  string `json:"detail"`
	} `json:"error"`
	Status string `json:"status"`
}

func (c *snowClient) tableURL(suffix string) string {
	return c.baseURL + "/api/now/table/" + c.table + suffix
}

// writeQuery makes the Table API resolve human-readable values on write:
// assignment_group by name ("Service Desk"), state/urgency by label ("In
// Progress", "3 - Low") — the way an agent naturally proposes them, rather than
// sys_ids and numeric choice codes. An unresolvable reference value is stored
// empty (never an error), so a mistyped group degrades to an unrouted incident,
// not a failed dispatch.
const writeQuery = "?sysparm_input_display_value=true"

// do issues one authenticated Table API request and returns the raw body and
// status. A transport-level failure (no HTTP response) returns a non-nil error;
// an HTTP error response (4xx/5xx) returns nil error with the status — the
// caller decides fatal-vs-retryable from the code (08 §6c).
func (c *snowClient) do(ctx context.Context, method, u string, body []byte) ([]byte, int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, nil
}

// createIncident POSTs a new record. The fields map is the incident body; the
// caller has already stamped correlation_id for idempotency. Returns the created
// record on 2xx.
func (c *snowClient) createIncident(ctx context.Context, fields map[string]any) (*snowRecord, int, error) {
	body, err := json.Marshal(fields)
	if err != nil {
		return nil, 0, err
	}
	raw, status, err := c.do(ctx, http.MethodPost, c.tableURL("")+writeQuery, body)
	if err != nil {
		return nil, 0, err
	}
	if status < 200 || status >= 300 {
		return nil, status, apiError(raw, status)
	}
	return decodeSingle(raw)
}

// patchIncident updates one record by sys_id. Returns the updated record.
func (c *snowClient) patchIncident(ctx context.Context, sysID string, fields map[string]any) (*snowRecord, int, error) {
	body, err := json.Marshal(fields)
	if err != nil {
		return nil, 0, err
	}
	raw, status, err := c.do(ctx, http.MethodPatch, c.tableURL("/"+url.PathEscape(sysID))+writeQuery, body)
	if err != nil {
		return nil, 0, err
	}
	if status < 200 || status >= 300 {
		return nil, status, apiError(raw, status)
	}
	return decodeSingle(raw)
}

// findOne runs an encoded-query GET and returns the first matching record, or
// (nil, status, nil) when the query matched nothing. Used for both the
// correlation_id idempotency lookup and number→sys_id resolution.
func (c *snowClient) findOne(ctx context.Context, query string) (*snowRecord, int, error) {
	q := url.Values{
		"sysparm_query":  {query},
		"sysparm_limit":  {"1"},
		"sysparm_fields": {"sys_id,number,state"},
	}
	raw, status, err := c.do(ctx, http.MethodGet, c.tableURL("")+"?"+q.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	if status < 200 || status >= 300 {
		return nil, status, apiError(raw, status)
	}
	var wrap struct {
		Result []snowRecord `json:"result"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, status, fmt.Errorf("unparseable query response (HTTP %d): %s", status, truncate(raw, 200))
	}
	if len(wrap.Result) == 0 {
		return nil, status, nil
	}
	return &wrap.Result[0], status, nil
}

// resolveSysID maps a caller-supplied incident identifier to its sys_id. A
// 32-char lowercase-hex string is already a sys_id (returned as-is, no call); a
// value like "INC0010042" is resolved via a number= query. Returns ("", 0, nil)
// when the number matched no record — the caller reports target-not-found. The
// status is propagated so an auth/transport failure on the lookup classifies
// correctly (08 §6c).
func (c *snowClient) resolveSysID(ctx context.Context, identifier string) (string, int, error) {
	if looksLikeSysID(identifier) {
		return identifier, 0, nil
	}
	rec, status, err := c.findOne(ctx, "number="+identifier)
	if err != nil {
		return "", status, err
	}
	if rec == nil {
		return "", status, nil
	}
	return rec.SysID, status, nil
}

func decodeSingle(raw []byte) (*snowRecord, int, error) {
	var wrap struct {
		Result snowRecord `json:"result"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return nil, 0, fmt.Errorf("unparseable record response: %s", truncate(raw, 200))
	}
	return &wrap.Result, 0, nil
}

// apiError turns a ServiceNow failure envelope into a Go error, falling back to
// the raw body when it does not parse.
func apiError(raw []byte, status int) error {
	var se snowError
	if err := json.Unmarshal(raw, &se); err == nil && se.Error.Message != "" {
		detail := se.Error.Message
		if se.Error.Detail != "" {
			detail += ": " + se.Error.Detail
		}
		return fmt.Errorf("HTTP %d: %s", status, detail)
	}
	return fmt.Errorf("HTTP %d: %s", status, truncate(raw, 200))
}

// looksLikeSysID reports whether s is a 32-character lowercase-hex ServiceNow
// sys_id, distinguishing it from a display number like "INC0010042".
func looksLikeSysID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, r := range s {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
		if !isHex {
			return false
		}
	}
	return true
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
