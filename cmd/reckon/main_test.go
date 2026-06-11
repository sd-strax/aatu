package main

import "testing"

// PID-file and process-liveness behavior is now owned by the runtime package
// (the boot path moved there); see runtime/runtime_test.go for those tests.

func TestOrderedComponentNames_PreferredOrder(_ *testing.T) {
	// orderedComponentNames orders: postgres → temporal → keycloak → backend,
	// then appends anything not in that list. The preferred-order guarantee is
	// what `reckon status` relies on for top-down dependency-order output.
}
