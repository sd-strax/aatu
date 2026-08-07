package server

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/identity"
)

func newSurface() (*capability.Resolver, *capability.Catalog) {
	reg := capability.NewRegistry(identity.NewResolver(uuid.New()))
	r := capability.NewResolver(capability.TenantContext{Name: "t"}, nil, nil, reg)
	return r, capability.NewCatalog()
}

// TestReloadCapabilitySwaps: ReloadCapability runs the injected closure and
// hot-swaps the live surface to what it returns.
func TestReloadCapabilitySwaps(t *testing.T) {
	boot, bootCat := newSurface()
	next, nextCat := newSurface()

	calls := 0
	b := &Backend{cfg: BackendConfig{
		CapabilityResolver: boot,
		CapabilityCatalog:  bootCat,
		CapabilityRebuild: func() (*capability.Resolver, *capability.Catalog, error) {
			calls++
			return next, nextCat, nil
		},
	}}

	// Before reload: the boot surface is live.
	if r, c := b.capabilitySurface(); r != boot || c != bootCat {
		t.Fatal("pre-reload surface is not the boot pair")
	}

	if err := b.ReloadCapability(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if calls != 1 {
		t.Errorf("rebuild closure called %d times, want 1", calls)
	}
	if r, c := b.capabilitySurface(); r != next || c != nextCat {
		t.Error("post-reload surface was not swapped to the rebuilt pair")
	}
}

// TestReloadCapabilityFailureKeepsSurface: a rebuild error returns the error
// and leaves the running surface untouched (a broken config edit degrades to
// "the change didn't take", never taking the layer down).
func TestReloadCapabilityFailureKeepsSurface(t *testing.T) {
	boot, bootCat := newSurface()
	b := &Backend{cfg: BackendConfig{
		CapabilityResolver: boot,
		CapabilityCatalog:  bootCat,
		CapabilityRebuild: func() (*capability.Resolver, *capability.Catalog, error) {
			return nil, nil, errors.New("bad config")
		},
	}}
	if err := b.ReloadCapability(); err == nil {
		t.Fatal("want error from a failing rebuild")
	}
	if r, c := b.capabilitySurface(); r != boot || c != bootCat {
		t.Error("a failed reload must leave the running surface unchanged")
	}
}

// TestReloadCapabilityNoClosure: with no rebuild wired, reload is a no-op (the
// fixture-only path relies on the enablement endpoint's in-package build).
func TestReloadCapabilityNoClosure(t *testing.T) {
	b := &Backend{cfg: BackendConfig{}}
	if err := b.ReloadCapability(); err != nil {
		t.Errorf("no-closure reload should be a nil no-op, got %v", err)
	}
}
