package module

import (
	"errors"

	"github.com/google/uuid"
)

// TenantID identifies a tenant in the deployment. It is the string form of a
// UUID so it round-trips cleanly with the UUID-typed tenant_id column that the
// data model carries on every tenant-scoped row (design/02-persistence.md,
// design/05-component-architecture.md §3).
type TenantID string

// SingleTenantID is the tenant ID used when no tenancy module is loaded.
// OSS installs are always tenants of one with this ID — "tenant 1" per
// 05-component-architecture.md §3. SingleTenantUUID is its parsed form, used
// where a uuid.UUID is needed (the aggregate write path, the schema DEFAULT).
const SingleTenantID TenantID = "00000000-0000-0000-0000-000000000001"

// SingleTenantUUID is SingleTenantID as a uuid.UUID. Keep it in sync with the
// DEFAULT on tenant_id columns in the aggregate/knowledge migrations.
var SingleTenantUUID = uuid.MustParse(string(SingleTenantID))

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
