package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/sd-strax/reckon/aggregate"
)

// wsURL rewrites an httptest http(s):// base URL to a ws:// stream URL.
func wsURL(base, query string) string {
	u := "ws://" + strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://") + "/api/stream"
	if query != "" {
		u += "?" + query
	}
	return u
}

// TestStream_HandshakeRejectsMissingToken asserts the WebSocket upgrade is
// refused with a 401 before any connection is established (design §5: validate
// at handshake).
func TestStream_HandshakeRejectsMissingToken(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, resp, err := websocket.Dial(ctx, wsURL(srv.URL, ""), nil)
	if err == nil {
		_ = conn.CloseNow()
		t.Fatal("expected handshake to fail without a token")
	}
	if resp == nil {
		t.Fatalf("expected an HTTP response on rejected handshake; got err=%v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("handshake status = %d; want 401", resp.StatusCode)
	}
}

// TestStream_ReceivesDeltaOnCreate connects, then drives a POST create and
// asserts the committed event arrives as a delta frame.
func TestStream_ReceivesDeltaOnCreate(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	token := mintToken(t, nil) // analyst role
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL(srv.URL, "access_token="+token), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()

	// First frame is the "ready" handshake confirmation.
	var ready Delta
	if err := wsjson.Read(ctx, conn, &ready); err != nil {
		t.Fatalf("read ready: %v", err)
	}
	if ready.Type != "ready" {
		t.Fatalf("first frame type = %q; want \"ready\"", ready.Type)
	}

	// Drive a create over HTTP.
	body := bytes.NewBufferString(`{"title":"PHISH-STREAM-1"}`)
	req, _ := http.NewRequest("POST", srv.URL+"/api/investigations", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d; want 201", resp.StatusCode)
	}

	// The delta should arrive on the stream.
	var delta Delta
	if err := wsjson.Read(ctx, conn, &delta); err != nil {
		t.Fatalf("read delta: %v", err)
	}
	if delta.Type != "event" {
		t.Errorf("delta type = %q; want \"event\"", delta.Type)
	}
	if delta.EventType != aggregate.EventTypeCreated {
		t.Errorf("delta event_type = %q; want %q", delta.EventType, aggregate.EventTypeCreated)
	}
	if delta.SequenceNo != 1 {
		t.Errorf("delta sequence_no = %d; want 1", delta.SequenceNo)
	}
	if delta.AggregateID == "" {
		t.Error("delta aggregate_id is empty")
	}
}

// TestStream_DropsOnTokenExpiry connects with a token that expires shortly and
// asserts the server closes the connection with a policy-violation code (design
// §5: "expired tokens cause connection drop").
func TestStream_DropsOnTokenExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	now := time.Now()
	token := mintToken(t, map[string]any{
		"exp": now.Add(2 * time.Second).Unix(),
		"iat": now.Unix(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL(srv.URL, "access_token="+token), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseNow()

	// Read until the server drops us. The expiry timer fires ~2s out; the
	// "ready" frame comes first, then the close.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_, _, rerr := conn.Read(ctx)
		if rerr == nil {
			continue // "ready" frame or any pre-expiry traffic
		}
		if status := websocket.CloseStatus(rerr); status == websocket.StatusPolicyViolation {
			return // expected: dropped on expiry
		}
		t.Fatalf("connection closed with %v; want StatusPolicyViolation", rerr)
	}
	t.Fatal("connection was not dropped within the expiry window")
}
