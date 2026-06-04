package module

import "errors"

// TenantID identifies a tenant in the deployment.
type TenantID string

// SingleTenantID is the tenant ID used when no tenancy module is loaded.
// OSS installs are always tenants of one with this ID.
const SingleTenantID TenantID = "__single__"

// ErrModuleDisabled is returned by stub or disabled-module methods that need
// to indicate a module-specific operation is not available.
var ErrModuleDisabled = errors.New("module disabled")

// Registry is the set of paid modules that may be loaded into a binary.
// The OSS binary always installs disabled stubs; the paid binary installs
// real implementations when activated by config.
//
// The Registry is the only injection surface between OSS and paid: OSS code
// reads from the registry through the interface methods; it never imports
// paid packages directly. This is what makes the open-core seam architectural
// rather than aspirational.
type Registry struct {
	Tenancy    TenancyModule
	Governance GovernanceModule
}
