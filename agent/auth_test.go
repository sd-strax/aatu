package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeIDP is a minimal Keycloak token endpoint. It counts password vs. refresh
// grants and can be told to reject refresh (simulating an expired refresh token
// / SSO idle timeout) so the login-fallback path is exercisable.
type fakeIDP struct {
	srv           *httptest.Server
	mu            sync.Mutex
	passwordCount int
	refreshCount  int
	rejectRefresh bool
	expiresIn     int // access-token TTL to advertise; 0 → omit
	seq           int // makes each issued access token distinct
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	f := &fakeIDP{expiresIn: 3600}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		grant := r.Form.Get("grant_type")
		switch grant {
		case "password":
			f.passwordCount++
		case "refresh_token":
			f.refreshCount++
			if f.rejectRefresh {
				http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "unexpected grant", http.StatusBadRequest)
			return
		}
		f.seq++
		body := map[string]any{
			"access_token":  fmt.Sprintf("access-%s-%d", grant, f.seq),
			"refresh_token": fmt.Sprintf("refresh-%d", f.seq),
		}
		if f.expiresIn > 0 {
			body["expires_in"] = f.expiresIn
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) counts() (pw, rt int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.passwordCount, f.refreshCount
}

// TestCredential_InitialLogin: NewCredential logs in once (password grant) and
// yields that token without re-hitting the IdP while it is fresh.
func TestCredential_InitialLogin(t *testing.T) {
	idp := newFakeIDP(t)
	c, err := NewCredential(context.Background(), idp.srv.URL, "reckon", "u", "p")
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
	// A second Token() while the first is fresh must NOT hit the IdP again.
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatalf("Token#2: %v", err)
	}
	if pw, rt := idp.counts(); pw != 1 || rt != 0 {
		t.Errorf("grants = password:%d refresh:%d; want 1/0 (cached while fresh)", pw, rt)
	}
}

// TestCredential_RefreshesNearExpiry: a cached token within refreshSkew of
// expiry is renewed via the refresh-token grant, not a fresh password login.
func TestCredential_RefreshesNearExpiry(t *testing.T) {
	idp := newFakeIDP(t)
	c, err := NewCredential(context.Background(), idp.srv.URL, "reckon", "u", "p")
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	// Force the cached token to look about-to-expire (package-internal test).
	c.mu.Lock()
	c.expiry = time.Now().Add(refreshSkew / 2)
	c.mu.Unlock()

	tok, err := c.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "access-refresh_token-2" {
		t.Errorf("token = %q; want the refreshed token", tok)
	}
	if pw, rt := idp.counts(); pw != 1 || rt != 1 {
		t.Errorf("grants = password:%d refresh:%d; want 1/1 (refresh, not re-login)", pw, rt)
	}
}

// TestCredential_FallsBackToLoginWhenRefreshRejected: when the refresh token is
// no longer valid (SSO idle timeout), renewal falls back to a full password
// login with the held credentials rather than failing.
func TestCredential_FallsBackToLoginWhenRefreshRejected(t *testing.T) {
	idp := newFakeIDP(t)
	c, err := NewCredential(context.Background(), idp.srv.URL, "reckon", "u", "p")
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	idp.mu.Lock()
	idp.rejectRefresh = true
	idp.mu.Unlock()

	tok, err := c.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh should fall back to login, got error: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token after fallback login")
	}
	pw, rt := idp.counts()
	if rt != 1 {
		t.Errorf("refresh grants = %d; want 1 (attempted then rejected)", rt)
	}
	if pw != 2 {
		t.Errorf("password grants = %d; want 2 (initial login + fallback)", pw)
	}
}

// countingSource is a TokenSource that hands out a stale token until Refresh is
// called — for asserting the Client's 401 retry.
type countingSource struct {
	mu        sync.Mutex
	token     string
	refreshed int
}

func (s *countingSource) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token, nil
}

func (s *countingSource) Refresh(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshed++
	s.token = "fresh"
	return s.token, nil
}

// TestClient_RetriesOn401: a backend that rejects the stale token (401) but
// accepts the refreshed one must see the Client force one refresh and retry, so
// the call ultimately succeeds — the long-idle-session recovery path.
func TestClient_RetriesOn401(t *testing.T) {
	var got401, got200 int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fresh" {
			got401++
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		got200++
		_ = json.NewEncoder(w).Encode(Investigation{AggregateID: "inv-1", Title: "T", Status: "active"})
	}))
	t.Cleanup(srv.Close)

	src := &countingSource{token: "stale"}
	c := NewClient(srv.URL, src, StaticToken("H"))

	inv, err := c.GetInvestigation(context.Background(), "inv-1")
	if err != nil {
		t.Fatalf("GetInvestigation should recover via refresh+retry: %v", err)
	}
	if inv.AggregateID != "inv-1" {
		t.Errorf("investigation = %+v; want inv-1", inv)
	}
	if src.refreshed != 1 {
		t.Errorf("refreshes = %d; want exactly 1 (single 401 retry)", src.refreshed)
	}
	if got401 != 1 || got200 != 1 {
		t.Errorf("backend saw 401:%d 200:%d; want 1/1", got401, got200)
	}
}
