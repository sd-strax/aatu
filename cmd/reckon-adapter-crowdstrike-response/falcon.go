package main

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

// falconClient is a minimal native client for the two Falcon endpoints this
// adapter needs: OAuth2 client-credentials token minting and the device-action
// call. Deliberately hand-rolled (no SDK): the surface is two endpoints, and a
// native adapter's whole point is a static binary with vendored-nothing
// (12 §2).
type falconClient struct {
	baseURL      string
	clientID     string
	clientSecret string
	memberCID    string
	httpc        *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func newFalconClient(baseURL, clientID, clientSecret, memberCID string) *falconClient {
	return &falconClient{
		baseURL:      strings.TrimRight(baseURL, "/"),
		clientID:     clientID,
		clientSecret: clientSecret,
		memberCID:    memberCID,
		httpc:        &http.Client{Timeout: 30 * time.Second},
	}
}

// bearer returns a valid OAuth2 access token, minting one when absent or
// within the refresh margin of expiry (POST /oauth2/token, client
// credentials; member_cid scopes the token to a child tenant CID (member_cid)).
func (c *falconClient) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiry.Add(-30*time.Second)) {
		return c.token, nil
	}

	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	if c.memberCID != "" {
		form.Set("member_cid", c.memberCID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/oauth2/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("falcon token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("falcon token: HTTP %d: %s", resp.StatusCode, truncate(body, 200))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("falcon token: unparseable response")
	}
	c.token = tok.AccessToken
	c.expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return c.token, nil
}

// deviceActionResponse is the Falcon batch-response convention: resources[]
// carries per-device outcomes, errors[] carries failures.
type deviceActionResponse struct {
	Resources []struct {
		ID string `json:"id"`
	} `json:"resources"`
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// deviceAction performs contain / lift_containment on device ids
// (POST /devices/entities/devices-actions/v2?action_name=…, scope hosts:write
// — PerformActionV2). Returns the parsed batch response; transport-level
// failure returns an error, which the caller must treat as UNKNOWN (the action
// may or may not have taken effect — 08 §6c).
func (c *falconClient) deviceAction(ctx context.Context, actionName string, ids []string) (*deviceActionResponse, int, error) {
	tokenStr, err := c.bearer(ctx)
	if err != nil {
		return nil, 0, err
	}
	payload, err := json.Marshal(map[string]any{"ids": ids})
	if err != nil {
		return nil, 0, err
	}
	u := c.baseURL + "/devices/entities/devices-actions/v2?action_name=" + url.QueryEscape(actionName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(string(payload)))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("falcon %s: %w", actionName, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var parsed deviceActionResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("falcon %s: HTTP %d, unparseable body: %s", actionName, resp.StatusCode, truncate(body, 200))
	}
	return &parsed, resp.StatusCode, nil
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
