package module

import "context"

// TenancyModule provides multi-tenant data-plane operations: tenant
// resolution, row-level-security activation, and the OSS-to-paid
// consolidation lift workflow.
//
// The disabled stub (DisabledTenancy) is the OSS-default behavior:
// single tenant, no RLS, no lift workflow available.
type TenancyModule interface {
	// Enabled reports whether a real tenancy module is loaded. OSS stubs
	// return false; paid implementations return true when activated.
	Enabled() bool

	// ApplyRLS returns the SQL fragment for tenant-aware queries, or the
	// original query unchanged when the module is disabled.
	ApplyRLS(ctx context.Context, query string) string

	// ResolveTenant returns the tenant context for the current request.
	// Disabled modules return SingleTenantID with no error.
	ResolveTenant(ctx context.Context) (TenantID, error)

	// LiftPath returns the consolidation lift workflow handle. Disabled
	// modules return ErrModuleDisabled.
	LiftPath() (LiftWorkflow, error)
}

// LiftWorkflow is a placeholder for the OSS-to-paid consolidation lift
// workflow handle. The real type lands in Phase I; today it exists so the
// interface signature is stable.
type LiftWorkflow interface {
	Name() string
}

// DisabledTenancy is the OSS-default tenancy stub. It is the value the OSS
// binary always installs in Registry.Tenancy; the paid binary installs it
// when paid.tenancy.enabled is false.
type DisabledTenancy struct{}

func (DisabledTenancy) Enabled() bool                                    { return false }
func (DisabledTenancy) ApplyRLS(_ context.Context, q string) string      { return q }
func (DisabledTenancy) ResolveTenant(_ context.Context) (TenantID, error) {
	return SingleTenantID, nil
}
func (DisabledTenancy) LiftPath() (LiftWorkflow, error) { return nil, ErrModuleDisabled }
