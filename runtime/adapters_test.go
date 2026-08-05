package runtime

import (
	"testing"

	"github.com/sd-strax/reckon/capability"
)

func TestRegisterNewVerbsAddsUnknownKeepsKnown(t *testing.T) {
	catalog := capability.NewCatalog()
	// A verb the engine already defines (its descriptor is authoritative).
	catalog.Register(capability.CapabilityDescriptor{Verb: "enumerate_logons", Intent: "engine intent"})

	registerNewVerbs(catalog, []capability.CapabilityDescriptor{
		// Adapter re-describes a known verb with a different intent — must NOT override.
		{Verb: "enumerate_logons", Intent: "adapter intent"},
		// A genuinely new adapter verb — must be added (this is what makes an
		// adapter's own verb visible to the agent).
		{Verb: "get_entity_context", Intent: "Fetch identity context."},
		{Verb: ""}, // ignored
	})

	if d, _ := catalog.Descriptor("enumerate_logons"); d.Intent != "engine intent" {
		t.Errorf("known verb overridden: intent = %q", d.Intent)
	}
	if d, ok := catalog.Descriptor("get_entity_context"); !ok || d.Intent != "Fetch identity context." {
		t.Errorf("new adapter verb not registered: %+v ok=%v", d, ok)
	}
	if len(catalog.Verbs()) != 2 {
		t.Errorf("catalog verbs = %v, want 2", catalog.Verbs())
	}
}
