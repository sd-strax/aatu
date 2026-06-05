// Package authz holds aatu's JWT validation, claim extraction, and the
// two-axis authorization evaluation skeleton.
//
// Gate 1 (RBAC) — covered by middleware in this package.
// Gate 2 (action authorization, CEL-based) — stubbed here; the real engine
// lands in Phase C (see aatu/action/).
//
// See aatu/design/05-component-architecture.md §5 for the architectural
// commitments this package implements.
package authz

// Role names registered in the bundled Keycloak `aatu` realm (see
// supervisor/keycloak_realm.json). The constants exist so callers
// reference role strings via a typed name rather than re-typing strings.
//
// Roles live in the IdP and travel in JWTs; aatu does not cache or mirror
// them. See aatu/CLAUDE.md "Architectural commitments".
const (
	RoleViewer         = "viewer"
	RoleAnalyst        = "analyst"
	RoleApprover       = "approver"
	RoleSeniorApprover = "senior_approver"
	RolePolicyAuthor   = "policy_author"
	RolePolicySigner   = "policy_signer"
	RoleSOPAuthor      = "sop_author"
	RoleSOPSigner      = "sop_signer"
	RoleTenantAdmin    = "tenant_admin"
	RoleAuditor        = "auditor"
)

// AllRoles is the canonical role set. The supervisor's bootstrapped realm
// registers exactly these.
var AllRoles = []string{
	RoleViewer,
	RoleAnalyst,
	RoleApprover,
	RoleSeniorApprover,
	RolePolicyAuthor,
	RolePolicySigner,
	RoleSOPAuthor,
	RoleSOPSigner,
	RoleTenantAdmin,
	RoleAuditor,
}
