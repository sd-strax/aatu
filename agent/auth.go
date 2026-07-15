package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// refreshSkew is how far before an access token's expiry a Credential
// proactively renews, so a token never expires between acquisition and use.
const refreshSkew = 30 * time.Second

// TokenSource yields bearer tokens for the backend Client. Token returns a
// currently-valid access token, refreshing silently if it is near expiry;
// Refresh forces a new token regardless of the cached one's computed validity —
// the backstop for when the backend rejects a token (401) earlier than expected
// (clock skew, server-side revocation). Both must be safe for concurrent use.
//
// The CLI supplies a Credential (password grant + refresh). The extension-era
// PKCE flow would implement the same interface with a browser-obtained refresh
// token and no stored password; the backend never learns the difference.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	Refresh(ctx context.Context) (string, error)
}

// staticToken is a fixed bearer token that never refreshes — for callers that
// already hold a token, and for tests.
type staticToken string

func (s staticToken) Token(context.Context) (string, error)   { return string(s), nil }
func (s staticToken) Refresh(context.Context) (string, error) { return string(s), nil }

// StaticToken returns a TokenSource that always yields tok.
func StaticToken(tok string) TokenSource { return staticToken(tok) }

// Credential is a resource-owner password grant against one Keycloak client id
// (supervisor/keycloak_realm.json enables it). It mints access tokens and keeps
// them fresh: proactively before expiry, via the refresh-token grant when that
// is still valid, falling back to a full re-login with the held credentials when
// it is not (e.g. after the realm's SSO session idle-timeout, which can outlive
// the access-token lifespan). Safe for concurrent use.
//
// Called once per client id: the same analyst credentials against `reckon`
// yield the human token, against `reckon-agent` the delegate token (the client
// stamps delegate_kind issuer-side — implementation/jwt-claims.md).
type Credential struct {
	issuer   string
	clientID string
	username string
	password string
	http     *http.Client

	mu           sync.Mutex
	accessToken  string
	refreshToken string
	expiry       time.Time
}

// NewCredential logs in immediately — so bad credentials fail fast at startup,
// not on the first backend call — and returns a refreshing TokenSource.
func NewCredential(ctx context.Context, issuer, clientID, username, password string) (*Credential, error) {
	c := &Credential{
		issuer:   issuer,
		clientID: clientID,
		username: username,
		password: password,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.login(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Token returns a valid access token, renewing if the cached one is within
// refreshSkew of expiry.
func (c *Credential) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accessToken != "" && time.Until(c.expiry) > refreshSkew {
		return c.accessToken, nil
	}
	return c.renew(ctx)
}

// Refresh forces a renewal regardless of the cached token's computed validity.
func (c *Credential) Refresh(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.renew(ctx)
}

// renew tries the refresh-token grant first, falling back to a full password
// login when the refresh token is gone. Caller holds c.mu.
func (c *Credential) renew(ctx context.Context) (string, error) {
	if c.refreshToken != "" {
		if err := c.refresh(ctx); err == nil {
			return c.accessToken, nil
		}
		// The refresh token itself has expired (SSO idle timeout) or was
		// revoked — fall through to a full re-login with the held credentials.
	}
	if err := c.login(ctx); err != nil {
		return "", err
	}
	return c.accessToken, nil
}

func (c *Credential) login(ctx context.Context) error {
	return c.grant(ctx, url.Values{
		"grant_type": {"password"},
		"client_id":  {c.clientID},
		"username":   {c.username},
		"password":   {c.password},
	})
}

func (c *Credential) refresh(ctx context.Context) error {
	return c.grant(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {c.clientID},
		"refresh_token": {c.refreshToken},
	})
}

// grant POSTs a token request and stores the result. Caller holds c.mu.
func (c *Credential) grant(ctx context.Context, form url.Values) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(c.issuer, "/")+"/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("token request to %s: %w", c.issuer, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request (%s, client %s): %d %s", c.issuer, c.clientID, resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return fmt.Errorf("token response carried no access_token")
	}
	c.accessToken = out.AccessToken
	c.refreshToken = out.RefreshToken
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Minute // conservative default if the IdP omitted expires_in
	}
	c.expiry = time.Now().Add(ttl)
	return nil
}
