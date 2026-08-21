package runtime

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	reckon "github.com/sd-strax/reckon"
)

// SeedResult reports the on-disk locations `reckon demo seed` materialized, so
// the config can be pointed at them and the CLI can tell the operator what was
// written.
type SeedResult struct {
	FixtureRoot      string // <base>/fixtures — cfg.Capability.FixtureRoot
	CapabilityConfig string // <base>/capability/<scenario>.yaml — cfg.Capability.ConfigPath
	Scenario         string // the seeded fixture scenario
	SOPDocs          string // <base>/sops — SOP markdown staged for live import
}

// SeedDemo materializes the embedded demo scenario + a merged tenant config
// under base (the install's config directory), so the demo world can serve
// /api/capabilities and run the request→dispatch→result→reverse action path
// against fixtures. It is the file-materializing half of `reckon demo seed`;
// the caller wires the returned paths into the config (ConfigPath/FixtureRoot)
// and flips demo.enabled. It does NOT touch config.yaml or any database.
//
// The capability (read) and action (write) example configs are merged into one
// file because runtime consumes a SINGLE config_path for both (buildCapability +
// buildActionActivities): their top-level keys are disjoint and both loaders
// ignore unknown keys (03 §3.2, 08 §4), so a concatenation is a valid config for
// each. Fixture JSON is copied verbatim into <base>/fixtures/<scenario>/.
//
// Seeding overwrites its own targets, so a re-seed is idempotent.
func SeedDemo(base string) (SeedResult, error) {
	scenario := reckon.DemoScenario
	fixtureRoot := filepath.Join(base, "fixtures")

	// 1. Copy the fixture scenario tree verbatim.
	srcDir := "fixtures/" + scenario // embed.FS always uses forward slashes
	entries, err := fs.ReadDir(reckon.DemoFS, srcDir)
	if err != nil {
		return SeedResult{}, fmt.Errorf("read embedded scenario %s: %w", scenario, err)
	}
	dstDir := filepath.Join(fixtureRoot, scenario)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return SeedResult{}, fmt.Errorf("create fixture dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue // the demo scenario is flat; nested dirs are not expected
		}
		data, err := reckon.DemoFS.ReadFile(srcDir + "/" + e.Name())
		if err != nil {
			return SeedResult{}, fmt.Errorf("read embedded fixture %s: %w", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, e.Name()), data, 0o644); err != nil {
			return SeedResult{}, fmt.Errorf("write fixture %s: %w", e.Name(), err)
		}
	}

	// 2. Merge the capability + action example configs into one tenant config.
	// The example configs are named for the workflow (DemoConfigBase), which
	// differs from the fixture scenario id (DemoScenario).
	capYAML, err := reckon.DemoFS.ReadFile("examples/capability/" + reckon.DemoConfigBase + ".yaml")
	if err != nil {
		return SeedResult{}, fmt.Errorf("read embedded capability config: %w", err)
	}
	actionYAML, err := reckon.DemoFS.ReadFile("examples/action/" + reckon.DemoConfigBase + ".yaml")
	if err != nil {
		return SeedResult{}, fmt.Errorf("read embedded action config: %w", err)
	}
	merged := mergeTenantConfigs(scenario, capYAML, actionYAML)

	configDir := filepath.Join(base, "capability")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return SeedResult{}, fmt.Errorf("create config dir: %w", err)
	}
	configPath := filepath.Join(configDir, reckon.DemoConfigBase+".yaml")
	if err := os.WriteFile(configPath, merged, 0o644); err != nil {
		return SeedResult{}, fmt.Errorf("write capability config: %w", err)
	}

	// 3. Stage the SOP markdown docs to disk. Unlike the prior-case summaries
	// (seeded into the corpus by the backend), the SOPs are imported LIVE during
	// the demo — the presenter walks the audience through a doc, then imports it
	// via the workbench. The file picker needs real files on disk, which a plain
	// install does not have (the docs live embedded in DemoFS), so materialize them.
	sopDir := filepath.Join(base, "sops")
	if err := os.MkdirAll(sopDir, 0o755); err != nil {
		return SeedResult{}, fmt.Errorf("create sop docs dir: %w", err)
	}
	sopEntries, err := fs.ReadDir(reckon.DemoFS, reckon.DemoKnowledgeSOPs)
	if err != nil {
		return SeedResult{}, fmt.Errorf("read embedded sop docs: %w", err)
	}
	for _, e := range sopEntries {
		if e.IsDir() {
			continue
		}
		data, err := reckon.DemoFS.ReadFile(reckon.DemoKnowledgeSOPs + "/" + e.Name())
		if err != nil {
			return SeedResult{}, fmt.Errorf("read embedded sop %s: %w", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(sopDir, e.Name()), data, 0o644); err != nil {
			return SeedResult{}, fmt.Errorf("stage sop %s: %w", e.Name(), err)
		}
	}

	return SeedResult{
		FixtureRoot:      fixtureRoot,
		CapabilityConfig: configPath,
		Scenario:         scenario,
		SOPDocs:          sopDir,
	}, nil
}

// mergeTenantConfigs concatenates the read + write example configs into one
// YAML document. Their top-level keys are disjoint (adapters/bindings/policies
// vs action_adapters/action_bindings), so a textual concatenation is a single
// valid mapping that both the capability and action loaders accept.
func mergeTenantConfigs(scenario string, capYAML, actionYAML []byte) []byte {
	header := "# Seeded by `reckon demo seed` for the bundled " + scenario + " demo scenario.\n" +
		"# Merged read (capability) + write (action) tenant config — runtime reads one\n" +
		"# config_path for both. Edit or replace to point at real adapters (Phase E/F).\n\n"
	out := make([]byte, 0, len(header)+len(capYAML)+len(actionYAML)+1)
	out = append(out, header...)
	out = append(out, capYAML...)
	out = append(out, '\n')
	out = append(out, actionYAML...)
	return out
}
