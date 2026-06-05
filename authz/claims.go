package authz

import (
	"slices"
)

// Claims is reckon's view of an authenticated user, extracted from a Keycloak
// JWT. The fields cover what the engine actually consumes; raw Keycloak
// claims (audience, jti, etc.) we ignore.
type Claims struct {
	// Subject is the IdP-assigned principal id (Keycloak `sub`).
	Subject string

	// PreferredUsername is the human-facing username (Keycloak
	// `preferred_username`). Useful for log lines; never load-bearing for
	// authorization decisions.
	PreferredUsername string

	// TenantID identifies the tenant this principal acts in. Comes from
	// the `tenant_id` claim that the governance module (paid) sets in
	// federated tokens. In OSS-solo deployments this is the singleton
	// tenant id; callers should default to that when the claim is absent.
	TenantID string

	// Roles is the union of realm-level + client-level roles carried in
	// the token. Keycloak nests these in `realm_access.roles` and
	// `resource_access.<client>.roles`.
	Roles []string

	// DelegateKind names the LLM delegate, if any, that produced this
	// request on the principal's behalf. Read from a custom `delegate_kind`
	// claim — empty when a human is acting directly.
	DelegateKind string

	// ExpiresAt is the token expiry in unix seconds. Re-checked by middleware
	// on every request; tokens past this point are rejected even if the
	// signature still validates.
	ExpiresAt int64
}

// HasRole reports whether the principal carries the named role.
func (c Claims) HasRole(role string) bool {
	return slices.Contains(c.Roles, role)
}

// HasAnyRole reports whether the principal carries at least one of the
// named roles.
func (c Claims) HasAnyRole(roles ...string) bool {
	for _, r := range roles {
		if slices.Contains(c.Roles, r) {
			return true
		}
	}
	return false
}

// rawClaims is the on-the-wire JSON shape we unmarshal from. Keycloak nests
// realm roles inside realm_access and client roles inside resource_access.
type rawClaims struct {
	Subject           string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	TenantID          string `json:"tenant_id"`
	DelegateKind      string `json:"delegate_kind"`
	ExpiresAt         int64  `json:"exp"`

	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`

	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

// toClaims flattens the on-wire shape into reckon's Claims. Realm and
// resource-access roles are merged; duplicates are squashed.
func (r rawClaims) toClaims(clientID string) Claims {
	roles := append([]string{}, r.RealmAccess.Roles...)
	if r.ResourceAccess != nil {
		if entry, ok := r.ResourceAccess[clientID]; ok {
			roles = append(roles, entry.Roles...)
		}
	}
	return Claims{
		Subject:           r.Subject,
		PreferredUsername: r.PreferredUsername,
		TenantID:          r.TenantID,
		Roles:             dedupe(roles),
		DelegateKind:      r.DelegateKind,
		ExpiresAt:         r.ExpiresAt,
	}
}

func dedupe(roles []string) []string {
	seen := make(map[string]struct{}, len(roles))
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}
