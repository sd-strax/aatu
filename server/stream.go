package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/sd-strax/reckon/authz"
)

// handleStream serves GET /api/stream, the projection-delta WebSocket.
//
// It authenticates at the handshake (design/05-component-architecture.md §5:
// "WebSocket connections validate at handshake"), subscribes the connection to
// the hub, and closes the connection when the presenting token expires (same
// §5: "expired tokens cause connection drop and re-auth prompt"). The token's
// expiry bounds the connection lifetime via a context deadline.
//
// verifier is passed in (rather than read from b.verifier) so the handshake
// shares exactly the verifier the rest of the router was built with, matching
// how RequireAuth closes over it.
func (b *Backend) handleStream(w http.ResponseWriter, r *http.Request, verifier *authz.Verifier) {
	if b.hub == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "stream hub not configured")
		return
	}

	claims, err := authenticateHandshake(r, verifier)
	if err != nil {
		// Reject before the upgrade so the client sees a normal 401, not a
		// WebSocket close. Mirrors RequireAuth's body shape.
		writeJSONError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return
	}

	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		// Accept has already written an error response.
		return
	}

	// Reads and writes are bound to the request lifetime, not the token
	// deadline. Expiry is handled separately by a timer that sends a clean
	// close frame: cancelling an in-flight Read would make the library abort
	// the TCP connection, which the client sees as an EOF rather than the
	// policy-violation close that tells it to re-auth.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Token expiry → clean policy-violation close (design §5). AfterFunc fires
	// off the read/write goroutines, so the Close races neither; the reader's
	// next Read then observes the close and unwinds the loop.
	if claims.ExpiresAt > 0 {
		timer := time.AfterFunc(time.Until(time.Unix(claims.ExpiresAt, 0)), func() {
			_ = conn.Close(websocket.StatusPolicyViolation, "token expired")
			cancel()
		})
		defer timer.Stop()
	}

	sub := b.hub.subscribe(r.URL.Query().Get("investigation"))
	defer b.hub.unsubscribe(sub)

	// Drain inbound frames in the background. We have no command frames yet
	// (interactive turns arrive in a later phase, at which point each frame is
	// re-validated per §5); reading is still required so the library processes
	// pings and observes the client's close. Any read error means the peer is
	// gone (or our own expiry close fired) — cancel to unwind the write loop.
	go func() {
		for {
			if _, _, rerr := conn.Read(ctx); rerr != nil {
				cancel()
				return
			}
		}
	}()

	// One "ready" frame confirms the stream is live before any deltas flow.
	if werr := writeFrame(ctx, conn, Delta{Type: "ready"}); werr != nil {
		_ = conn.CloseNow()
		return
	}

	for {
		select {
		case <-ctx.Done():
			// Expiry (timer already sent the policy-violation close), peer
			// disconnect, or server shutdown. CloseNow is a safety-net teardown
			// if no close frame was sent on this path.
			_ = conn.CloseNow()
			return
		case d, ok := <-sub.ch:
			if !ok {
				_ = conn.Close(websocket.StatusNormalClosure, "hub closed")
				return
			}
			if werr := writeFrame(ctx, conn, d); werr != nil {
				cancel()
				_ = conn.CloseNow()
				return
			}
		}
	}
}

// writeFrame writes one JSON delta with a bounded deadline so a stuck socket
// can't wedge the write loop.
func writeFrame(ctx context.Context, conn *websocket.Conn, d Delta) error {
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return wsjson.Write(wctx, conn, d)
}

// authenticateHandshake extracts and verifies the bearer token from a
// WebSocket upgrade request. Browsers cannot set the Authorization header on a
// WebSocket handshake, so the token is also accepted from the `access_token`
// query parameter; the Authorization header takes precedence. Non-browser
// clients (the VS Code extension, CLI) may use either.
func authenticateHandshake(r *http.Request, verifier *authz.Verifier) (authz.Claims, error) {
	raw, ok := handshakeBearer(r)
	if !ok {
		return authz.Claims{}, errors.New("missing token (Authorization: Bearer <t> header or access_token query param)")
	}
	return verifier.Verify(r.Context(), raw)
}

// handshakeBearer pulls the token from the Authorization header, falling back
// to the access_token query parameter.
func handshakeBearer(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, prefix) {
		if t := strings.TrimSpace(h[len(prefix):]); t != "" {
			return t, true
		}
	}
	if t := strings.TrimSpace(r.URL.Query().Get("access_token")); t != "" {
		return t, true
	}
	return "", false
}
