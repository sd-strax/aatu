package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// KeycloakAdmin is a minimal Keycloak Admin REST client, used by the
// `reckon dev-auth` command to provision a local/CI login principal and enable
// the direct-access (ROPC) grant AT RUNTIME. None of this ships in the realm
// import (supervisor/keycloak_realm.json) — the artifact carries no credentialed
// account and no password grant (implementation/jwt-claims.md). Provisioning is
// therefore a deliberate, out-of-band dev/CI act against a running instance,
// never a property of the distributed software.
//
// It authenticates with the master-realm bootstrap admin (admin/admin by
// default; ensureBootstrapAdmin) via admin-cli, so it inherits the same "weak
// dev default, rotate in production" posture as the console admin.
type KeycloakAdmin struct {
	baseURL string // e.g. http://localhost:8543 (no trailing slash)
	realm   string // the application realm (e.g. reckon)
	http    *http.Client
	token   string
}

// NewKeycloakAdmin builds an admin client against baseURL for the given
// application realm. Call Login before any provisioning call.
func NewKeycloakAdmin(baseURL, realm string) *KeycloakAdmin {
	return &KeycloakAdmin{
		baseURL: strings.TrimRight(baseURL, "/"),
		realm:   realm,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Login obtains an admin access token via the master realm's admin-cli client
// (direct-access grant). admin-cli ships with ROPC enabled in every Keycloak —
// it is the client kcadm itself uses — so this needs no realm change.
func (a *KeycloakAdmin) Login(ctx context.Context, adminUser, adminPass string) error {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {adminUser},
		"password":   {adminPass},
	}
	endpoint := a.baseURL + "/realms/master/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("admin login: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin login: %s (%s) — is the bootstrap admin present and the master admin-cli grant enabled?", resp.Status, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return fmt.Errorf("admin login: decode token: %w", err)
	}
	if tok.AccessToken == "" {
		return fmt.Errorf("admin login: empty access_token")
	}
	a.token = tok.AccessToken
	return nil
}

// SetDirectAccessGrants toggles ROPC on a client by clientId (not the internal
// uuid). It reads the full client representation and writes it back with the
// one field changed, so no other client config is disturbed.
func (a *KeycloakAdmin) SetDirectAccessGrants(ctx context.Context, clientID string, enabled bool) error {
	var clients []map[string]any
	if err := a.do(ctx, http.MethodGet, "/clients?clientId="+url.QueryEscape(clientID), nil, &clients); err != nil {
		return fmt.Errorf("lookup client %q: %w", clientID, err)
	}
	if len(clients) == 0 {
		return fmt.Errorf("client %q not found in realm %q", clientID, a.realm)
	}
	rep := clients[0]
	id, _ := rep["id"].(string)
	if id == "" {
		return fmt.Errorf("client %q has no id", clientID)
	}
	rep["directAccessGrantsEnabled"] = enabled
	if err := a.do(ctx, http.MethodPut, "/clients/"+id, rep, nil); err != nil {
		return fmt.Errorf("update client %q: %w", clientID, err)
	}
	return nil
}

// EnsureUser creates the user if absent (enabled, verified email so the direct
// grant isn't blocked by a required action), (re)sets a non-temporary password,
// and assigns the given realm roles. Idempotent. Returns whether it created the
// user (vs updated an existing one).
func (a *KeycloakAdmin) EnsureUser(ctx context.Context, username string, roles []string, password string) (created bool, err error) {
	id, err := a.findUser(ctx, username)
	if err != nil {
		return false, err
	}
	if id == "" {
		user := map[string]any{
			"username":      username,
			"enabled":       true,
			"emailVerified": true,
			"email":         username + "@localhost",
		}
		if err := a.do(ctx, http.MethodPost, "/users", user, nil); err != nil {
			return false, fmt.Errorf("create user %q: %w", username, err)
		}
		if id, err = a.findUser(ctx, username); err != nil {
			return false, err
		}
		if id == "" {
			return false, fmt.Errorf("user %q not found after create", username)
		}
		created = true
	}

	cred := map[string]any{"type": "password", "value": password, "temporary": false}
	if err := a.do(ctx, http.MethodPut, "/users/"+id+"/reset-password", cred, nil); err != nil {
		return created, fmt.Errorf("set password for %q: %w", username, err)
	}

	var roleReps []map[string]any
	for _, role := range roles {
		var rep map[string]any
		if err := a.do(ctx, http.MethodGet, "/roles/"+url.PathEscape(role), nil, &rep); err != nil {
			return created, fmt.Errorf("lookup role %q: %w", role, err)
		}
		roleReps = append(roleReps, rep)
	}
	if len(roleReps) > 0 {
		// Role assignment is additive and idempotent on the Keycloak side.
		if err := a.do(ctx, http.MethodPost, "/users/"+id+"/role-mappings/realm", roleReps, nil); err != nil {
			return created, fmt.Errorf("assign roles to %q: %w", username, err)
		}
	}
	return created, nil
}

// DevAuthOptions parameterizes a dev/CI provisioning run (the `reckon dev-auth`
// command). Everything here mutates a RUNNING Keycloak, never the shipped realm
// import.
type DevAuthOptions struct {
	BaseURL   string   // http://localhost:<kc http port>
	Realm     string   // application realm
	AdminUser string   // master bootstrap admin (default admin)
	AdminPass string   // master bootstrap admin password (default admin)
	Username  string   // principal to provision
	Password  string   // its non-temporary password
	Roles     []string // realm roles to grant
	ROPCFor   []string // client ids to enable the direct-access grant on
}

// ProvisionDevAuth logs in as the bootstrap admin, enables the direct-access
// grant on the named clients, and ensures the principal exists with the given
// password and roles. It is the whole of what `reckon dev-auth` does. Returns
// whether the user was created (vs already present).
func ProvisionDevAuth(ctx context.Context, opts DevAuthOptions) (created bool, err error) {
	admin := NewKeycloakAdmin(opts.BaseURL, opts.Realm)
	if err := admin.Login(ctx, opts.AdminUser, opts.AdminPass); err != nil {
		return false, err
	}
	for _, clientID := range opts.ROPCFor {
		if err := admin.SetDirectAccessGrants(ctx, clientID, true); err != nil {
			return false, err
		}
	}
	return admin.EnsureUser(ctx, opts.Username, opts.Roles, opts.Password)
}

// findUser returns the internal user id for an exact username match, or "" if
// the user does not exist.
func (a *KeycloakAdmin) findUser(ctx context.Context, username string) (string, error) {
	var users []map[string]any
	q := "/users?exact=true&username=" + url.QueryEscape(username)
	if err := a.do(ctx, http.MethodGet, q, nil, &users); err != nil {
		return "", fmt.Errorf("lookup user %q: %w", username, err)
	}
	for _, u := range users {
		if u["username"] == username {
			if id, _ := u["id"].(string); id != "" {
				return id, nil
			}
		}
	}
	return "", nil
}

// do issues one Admin-REST call under /admin/realms/{realm}, with the bearer
// token, optionally decoding a JSON response into out.
func (a *KeycloakAdmin) do(ctx context.Context, method, path string, in, out any) error {
	if a.token == "" {
		return fmt.Errorf("keycloak admin: not logged in")
	}
	var body io.Reader
	if in != nil {
		enc, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(enc)
	}
	endpoint := a.baseURL + "/admin/realms/" + url.PathEscape(a.realm) + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s (%s)", method, path, resp.Status, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode %s %s: %w", method, path, err)
		}
	}
	return nil
}
