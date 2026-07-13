package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PasswordToken obtains an access token from Keycloak via the direct-access
// grant (resource owner password credentials) — the CLI's v0 login against the
// bundled realm, whose clients enable it (supervisor/keycloak_realm.json). The
// PKCE browser flow is the extension-era polish; the engine only ever sees the
// resulting JWT either way.
//
// Called once per client id: the same analyst credentials against `reckon`
// yield the human token, against `reckon-agent` the delegate token (the client
// stamps delegate_kind issuer-side — implementation/jwt-claims.md).
func PasswordToken(ctx context.Context, issuer, clientID, username, password string) (string, error) {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(issuer, "/")+"/protocol/openid-connect/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpc := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request to %s: %w", issuer, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request (%s, client %s): %d %s", issuer, clientID, resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("token response carried no access_token")
	}
	return out.AccessToken, nil
}
