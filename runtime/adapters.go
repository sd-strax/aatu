package runtime

import (
	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/capability"
	"github.com/sd-strax/reckon/internal/adapterplugin"
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
