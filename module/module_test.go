package module

import (
	"context"
	"errors"
	"testing"
)

func TestDisabledTenancyBaseline(t *testing.T) {
	var m TenancyModule = DisabledTenancy{}
	if m.Enabled() {
		t.Errorf("DisabledTenancy.Enabled() = true; want false")
	}
	if got := m.ApplyRLS(context.Background(), "SELECT * FROM t"); got != "SELECT * FROM t" {
		t.Errorf("DisabledTenancy.ApplyRLS rewrote query: %q", got)
	}
	tid, err := m.ResolveTenant(context.Background())
	if err != nil {
		t.Errorf("DisabledTenancy.ResolveTenant returned error: %v", err)
	}
	if tid != SingleTenantID {
		t.Errorf("DisabledTenancy.ResolveTenant = %q; want %q", tid, SingleTenantID)
	}
	if _, err := m.LiftPath(); !errors.Is(err, ErrModuleDisabled) {
		t.Errorf("DisabledTenancy.LiftPath err = %v; want ErrModuleDisabled", err)
	}
}

func TestDisabledGovernanceBaseline(t *testing.T) {
	var m GovernanceModule = DisabledGovernance{}
	if m.Enabled() {
		t.Errorf("DisabledGovernance.Enabled() = true; want false")
	}
	if mode := m.GovernanceMode(); mode != Lightweight {
		t.Errorf("DisabledGovernance.GovernanceMode = %q; want %q", mode, Lightweight)
	}
	if m.SignoffRequired(ArtifactType("sop")) {
		t.Errorf("DisabledGovernance.SignoffRequired = true; want false")
	}
	if tmpls := m.RoleMappingTemplates(); len(tmpls) != 0 {
		t.Errorf("DisabledGovernance.RoleMappingTemplates non-empty: %v", tmpls)
	}
}

func TestRegistryComposition(t *testing.T) {
	reg := Registry{
		Tenancy:    DisabledTenancy{},
		Governance: DisabledGovernance{},
	}
	if reg.Tenancy.Enabled() || reg.Governance.Enabled() {
		t.Errorf("disabled-stub registry reports enabled module: %+v", reg)
	}
}
