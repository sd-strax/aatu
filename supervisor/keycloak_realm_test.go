package supervisor

import (
	"encoding/json"
	"testing"

	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/internal/branding"
)

// realmDoc is the subset of the Keycloak realm import we assert on. The realm
// JSON is the claim contract the engine depends on (authz/), expressed as IdP
// config — this test guards that contract structurally, without needing a
// running Keycloak, so a bad edit to the embedded realm fails at `go test`
// rather than at an analyst's first login.
type realmDoc struct {
	Realm string `json:"realm"`
	Roles struct {
		Realm []struct {
			Name string `json:"name"`
		} `json:"realm"`
	} `json:"roles"`
	Clients []realmClient `json:"clients"`
	Users   []realmUser   `json:"users"`
}

type realmUser struct {
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	Enabled         bool     `json:"enabled"`
	RequiredActions []string `json:"requiredActions"`
	Credentials     []struct {
		Type      string `json:"type"`
		Temporary bool   `json:"temporary"`
	} `json:"credentials"`
}

type realmClient struct {
	ClientID        string `json:"clientId"`
	Description     string `json:"description"`
	PublicClient    bool   `json:"publicClient"`
	ProtocolMappers []struct {
		Name           string            `json:"name"`
		ProtocolMapper string            `json:"protocolMapper"`
		Config         map[string]string `json:"config"`
	} `json:"protocolMappers"`
}

func parseRealm(t *testing.T) realmDoc {
	t.Helper()
	var doc realmDoc
	if err := json.Unmarshal(defaultRealmJSON, &doc); err != nil {
		t.Fatalf("embedded realm json does not parse: %v", err)
	}
	return doc
}

func (c realmClient) mapper(protocolMapper string) (map[string]string, bool) {
	for _, m := range c.ProtocolMappers {
		if m.ProtocolMapper == protocolMapper {
			return m.Config, true
		}
	}
	return nil, false
}

func findClient(doc realmDoc, clientID string) (realmClient, bool) {
	for _, c := range doc.Clients {
		if c.ClientID == clientID {
			return c, true
		}
	}
	return realmClient{}, false
}

// keycloakClientDescriptionMax is Keycloak's CLIENT.DESCRIPTION column width
// (VARCHAR(255)). A longer description aborts the realm import with a SQL
// truncation error and Keycloak never starts — a failure invisible to every
// mock-issuer test, so it must be guarded here against the embedded realm.
const keycloakClientDescriptionMax = 255

// TestRealm_ClientDescriptionsFitKeycloakColumn: no client description exceeds
// Keycloak's column limit. Regression guard for the import failure the first
// real `reckon start` surfaced (a 473-char reckon-agent description).
func TestRealm_ClientDescriptionsFitKeycloakColumn(t *testing.T) {
	doc := parseRealm(t)
	for _, c := range doc.Clients {
		if n := len(c.Description); n > keycloakClientDescriptionMax {
			t.Errorf("client %q description is %d chars; Keycloak's column caps at %d (realm import will abort)",
				c.ClientID, n, keycloakClientDescriptionMax)
		}
	}
}

// TestRealm_BundledUserIsLoginReady: the seeded reckon-admin user must be able
// to authenticate via the direct-access grant out of the box (the CLI login
// path). Keycloak 26 refuses the grant with "Account is not fully set up" if a
// required profile attribute (email) is missing, the password is temporary
// (forces UPDATE_PASSWORD), or a required action is pending. The first real
// `reckon start` hit exactly this; guard all three so a fresh install can log in
// without an admin-console detour.
func TestRealm_BundledUserIsLoginReady(t *testing.T) {
	doc := parseRealm(t)
	if len(doc.Users) == 0 {
		t.Fatal("realm defines no bundled user; the first-run login has no account")
	}
	for _, u := range doc.Users {
		if !u.Enabled {
			t.Errorf("user %q is disabled", u.Username)
		}
		if u.Email == "" {
			t.Errorf("user %q has no email; Keycloak's user profile requires it or the grant fails", u.Username)
		}
		if len(u.RequiredActions) != 0 {
			t.Errorf("user %q has pending required actions %v; the direct grant would fail", u.Username, u.RequiredActions)
		}
		var hasPassword bool
		for _, c := range u.Credentials {
			if c.Type != "password" {
				continue
			}
			hasPassword = true
			if c.Temporary {
				t.Errorf("user %q ships a temporary password; it forces UPDATE_PASSWORD and blocks the direct grant", u.Username)
			}
		}
		if !hasPassword {
			t.Errorf("user %q has no password credential", u.Username)
		}
	}
}

// TestRealm_DefinesEveryEngineRole: every role the engine authorizes against
// (authz.AllRoles) must exist in the realm, or a token can never carry it and
// the corresponding capability is unreachable.
func TestRealm_DefinesEveryEngineRole(t *testing.T) {
	doc := parseRealm(t)
	if doc.Realm != branding.CLI {
		t.Errorf("realm name = %q; want %q", doc.Realm, branding.CLI)
	}
	defined := make(map[string]bool, len(doc.Roles.Realm))
	for _, r := range doc.Roles.Realm {
		defined[r.Name] = true
	}
	for _, role := range authz.AllRoles {
		if !defined[role] {
			t.Errorf("engine role %q is not defined in the realm", role)
		}
	}
}

// TestRealm_HumanClientHasNoDelegateClaim: the `reckon` client is the human
// principal path — a token from it must NOT carry delegate_kind, or a human
// request would be mistaken for an AI-delegated one.
func TestRealm_HumanClientHasNoDelegateClaim(t *testing.T) {
	doc := parseRealm(t)
	human, ok := findClient(doc, "reckon")
	if !ok {
		t.Fatal("realm is missing the `reckon` (human) client")
	}
	if !human.PublicClient {
		t.Error("`reckon` client must be public (PKCE, no secret in the extension/CLI)")
	}
	if _, ok := human.mapper("oidc-hardcoded-claim-mapper"); ok {
		t.Error("`reckon` (human) client must not stamp delegate_kind")
	}
	// It still needs the audience mapper so `client_id: reckon` audience checks pass.
	if _, ok := human.mapper("oidc-audience-mapper"); !ok {
		t.Error("`reckon` client is missing the audience mapper")
	}
}

// TestRealm_AgentClientStampsDelegateKind: the `reckon-agent` client is the
// AI-delegate path. It must stamp delegate_kind issuer-side (a hardcoded-claim
// mapper — never caller-supplied), so the engine's Actor.Kind derivation, the
// AI-write-protection allowlist, and Gate 2's baseline DENY are all trustworthy.
// This is the structural guarantee behind implementation/jwt-claims.md.
func TestRealm_AgentClientStampsDelegateKind(t *testing.T) {
	doc := parseRealm(t)
	agent, ok := findClient(doc, "reckon-agent")
	if !ok {
		t.Fatal("realm is missing the `reckon-agent` (delegate) client")
	}
	if !agent.PublicClient {
		t.Error("`reckon-agent` client must be public")
	}
	cfg, ok := agent.mapper("oidc-hardcoded-claim-mapper")
	if !ok {
		t.Fatal("`reckon-agent` client must carry a hardcoded-claim mapper for delegate_kind")
	}
	if cfg["claim.name"] != "delegate_kind" {
		t.Errorf("agent mapper claim.name = %q; want delegate_kind", cfg["claim.name"])
	}
	if cfg["claim.value"] == "" {
		t.Error("agent mapper claim.value (the delegate vendor) is empty")
	}
	// The claim MUST land in the access token — that is the token the backend
	// verifies; an id-token-only claim would never reach the engine.
	if cfg["access.token.claim"] != "true" {
		t.Error("delegate_kind must be set on the access token (access.token.claim=true)")
	}
	// The agent client needs the audience mapper too, or delegated tokens fail
	// every client_id-locked deployment while human tokens keep working.
	audCfg, ok := agent.mapper("oidc-audience-mapper")
	if !ok {
		t.Fatal("`reckon-agent` client is missing the audience mapper")
	}
	if audCfg["included.client.audience"] != "reckon" {
		t.Errorf("agent audience = %q; want reckon", audCfg["included.client.audience"])
	}
	// The engine reads delegate_kind out of the access token; assert the parser
	// would actually see it by round-tripping a synthetic token body.
	body := `{"sub":"analyst-1","delegate_kind":"` + cfg["claim.value"] + `","realm_access":{"roles":["analyst"]}}`
	var raw struct {
		DelegateKind string `json:"delegate_kind"`
	}
	if err := json.Unmarshal([]byte(body), &raw); err != nil || raw.DelegateKind != cfg["claim.value"] {
		t.Errorf("delegate_kind claim shape mismatch: %v / %q", err, raw.DelegateKind)
	}
}
