package authz

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestRawClaims_ToClaims_MergesRealmAndResourceRoles(t *testing.T) {
	rawJSON := []byte(`{
		"sub": "abc-123",
		"preferred_username": "alice",
		"tenant_id": "tenant-1",
		"delegate_kind": "anthropic:claude-opus-4-8",
		"exp": 1780000000,
		"realm_access": { "roles": ["analyst", "viewer"] },
		"resource_access": {
			"reckon":    { "roles": ["approver", "viewer"] },
			"account": { "roles": ["manage-account"] }
		}
	}`)

	var r rawClaims
	if err := json.Unmarshal(rawJSON, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := r.toClaims("reckon")
	if got.Subject != "abc-123" {
		t.Errorf("Subject = %q; want abc-123", got.Subject)
	}
	if got.PreferredUsername != "alice" {
		t.Errorf("PreferredUsername = %q; want alice", got.PreferredUsername)
	}
	if got.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q; want tenant-1", got.TenantID)
	}
	if got.DelegateKind != "anthropic:claude-opus-4-8" {
		t.Errorf("DelegateKind = %q", got.DelegateKind)
	}
	if got.ExpiresAt != 1780000000 {
		t.Errorf("ExpiresAt = %d", got.ExpiresAt)
	}

	// Realm roles + the reckon resource_access roles merged, deduplicated.
	// The 'account' resource-access entry is intentionally ignored — it
	// doesn't match our clientID.
	wantRoles := []string{"analyst", "viewer", "approver"}
	if !sameUnordered(got.Roles, wantRoles) {
		t.Errorf("Roles = %v; want unordered match with %v", got.Roles, wantRoles)
	}
}

func TestClaims_HasRole(t *testing.T) {
	c := Claims{Roles: []string{"analyst", "approver"}}
	if !c.HasRole("analyst") {
		t.Error("HasRole(analyst) = false")
	}
	if c.HasRole("auditor") {
		t.Error("HasRole(auditor) = true")
	}
}

func TestClaims_HasAnyRole(t *testing.T) {
	c := Claims{Roles: []string{"viewer"}}
	if !c.HasAnyRole("viewer", "auditor") {
		t.Error("HasAnyRole(viewer,auditor) = false")
	}
	if c.HasAnyRole("auditor", "tenant_admin") {
		t.Error("HasAnyRole(auditor,tenant_admin) = true")
	}
	if c.HasAnyRole() {
		t.Error("HasAnyRole() on empty list returned true")
	}
}

func TestRawClaims_ToClaims_NoResourceAccess(t *testing.T) {
	r := rawClaims{Subject: "x"}
	r.RealmAccess.Roles = []string{"viewer"}
	got := r.toClaims("reckon")
	if !slices.Equal(got.Roles, []string{"viewer"}) {
		t.Errorf("Roles = %v", got.Roles)
	}
}

func sameUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac, bc := append([]string{}, a...), append([]string{}, b...)
	slices.Sort(ac)
	slices.Sort(bc)
	return slices.Equal(ac, bc)
}
