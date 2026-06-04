package module

// GovernanceMode selects the SOP and policy lifecycle behavior.
//
// Lightweight is the OSS-default write-it-use-it model. Gated runs the
// draft → in-review → published → retired flow with explicit signoff roles.
// Both modes are recognized by the engine; the governance module's surface
// (review queues, signoff history, citation analytics) is what makes Gated
// operationally pleasant.
type GovernanceMode string

const (
	Lightweight GovernanceMode = "lightweight"
	Gated       GovernanceMode = "gated"
)

// ArtifactType names something governed by signoff rules — SOPs, policies,
// detection rules, and so on. The string values become a stable enum as
// artifact types are added.
type ArtifactType string

// RoleTemplate is a placeholder for an IdP role-mapping template the
// governance module ships (Okta/Entra/Google Workspace/Auth0/SAML/OIDC).
// The real type lands in Phase I.
type RoleTemplate struct {
	Name        string
	Description string
}

// GovernanceModule provides operational tooling around the SOP/policy
// lifecycle, federation setup, and signoff queues.
//
// The disabled stub (DisabledGovernance) returns Lightweight mode and no
// signoff requirements — matching the OSS-only baseline.
type GovernanceModule interface {
	// Enabled reports whether a real governance module is loaded.
	Enabled() bool

	// GovernanceMode returns the configured lifecycle mode. Disabled
	// modules always return Lightweight.
	GovernanceMode() GovernanceMode

	// SignoffRequired reports whether the given artifact type requires
	// explicit signoff. Always false in Lightweight; configurable in Gated.
	SignoffRequired(artifactType ArtifactType) bool

	// RoleMappingTemplates returns the federation role-mapping templates
	// the governance module ships. Disabled modules return nil.
	RoleMappingTemplates() []RoleTemplate
}

// DisabledGovernance is the OSS-default governance stub. It is the value
// the OSS binary always installs in Registry.Governance; the paid binary
// installs it when paid.governance.enabled is false.
type DisabledGovernance struct{}

func (DisabledGovernance) Enabled() bool                          { return false }
func (DisabledGovernance) GovernanceMode() GovernanceMode         { return Lightweight }
func (DisabledGovernance) SignoffRequired(_ ArtifactType) bool    { return false }
func (DisabledGovernance) RoleMappingTemplates() []RoleTemplate   { return nil }
