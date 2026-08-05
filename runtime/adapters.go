package runtime

import (
	"context"
	"log"
	"time"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
	"github.com/sd-strax/reckon/internal/branding"
)

// pluginReadAdapters builds the read facades (capability.Adapter) for every
// enabled out-of-process adapter instance in the capability tenant config
// (11 §5). The fixture class is built by the resolver itself; every other class
// is an out-of-process plugin drawn from the shared host, so an instance that
// also serves writes reuses the same process. Construction is spawn-free (the
// Plugin spawns lazily on first resolve).
func pluginReadAdapters(host *adapterplugin.Host, tc capability.TenantConfig) (map[string]capability.Adapter, error) {
	out := map[string]capability.Adapter{}
	for name, spec := range tc.Adapters {
		if !spec.Enabled || spec.Class == capability.ClassFixture {
			continue
		}
		p, err := host.Plugin(name, spec.Adapter, spec.Config)
		if err != nil {
			return nil, err
		}
		out[name] = adapterplugin.NewReadAdapter(p, spec.Reads)
	}
	return out, nil
}

// pluginWriteAdapters builds the write facades (action.WriteAdapter) for every
// enabled out-of-process adapter instance in the action tenant config (11 §5).
// The per-op `actions` list is the write allowlist — no wildcard (11 §5). It
// shares plugin processes with pluginReadAdapters through the same host, keyed
// by instance name.
func pluginWriteAdapters(host *adapterplugin.Host, ac action.TenantActionConfig) (map[string]action.WriteAdapter, error) {
	out := map[string]action.WriteAdapter{}
	for name, spec := range ac.Adapters {
		if !spec.Enabled || spec.Class == capability.ClassFixture {
			continue
		}
		p, err := host.Plugin(name, spec.Adapter, spec.Config)
		if err != nil {
			return nil, err
		}
		out[name] = adapterplugin.NewWriteAdapter(p, spec.Actions)
	}
	return out, nil
}

// reconcileCatalog registers each enabled out-of-process adapter's described
// read verbs into the capability catalog (11 §4.2: the adapter is the authority
// on which verbs EXIST; the engine keeps its own descriptor for a verb it
// already knows and only ADDS genuinely new adapter verbs, filtered by binding
// at ListCapabilities time). This is what makes an adapter's own verbs (e.g.
// get_entity_context) visible to the agent — the catalog otherwise carries only
// the engine's built-in verbs. An adapter that fails to describe is skipped with
// a warning: its verbs stay invisible (honest degradation), never a boot
// failure (an integration must not take the engine down).
func reconcileCatalog(host *adapterplugin.Host, tc capability.TenantConfig, catalog *capability.Catalog) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for name, spec := range tc.Adapters {
		if !spec.Enabled || spec.Class == capability.ClassFixture {
			continue
		}
		p, err := host.Plugin(name, spec.Adapter, spec.Config)
		if err != nil {
			log.Printf("%s: adapter %q catalog reconcile skipped: %v", branding.CLI, name, err)
			continue
		}
		desc, err := p.Describe(ctx)
		if err != nil {
			log.Printf("%s: adapter %q describe failed — its verbs stay unavailable: %v", branding.CLI, name, err)
			continue
		}
		registerNewVerbs(catalog, desc.Verbs)
	}
}

// registerNewVerbs adds descriptors for verbs the catalog does not already
// define. A verb the catalog knows keeps the engine's authoritative descriptor
// (11 §4.2); only new adapter verbs are added.
func registerNewVerbs(catalog *capability.Catalog, verbs []capability.CapabilityDescriptor) {
	for _, v := range verbs {
		if v.Verb == "" {
			continue
		}
		if _, known := catalog.Descriptor(v.Verb); !known {
			catalog.Register(v)
		}
	}
}
