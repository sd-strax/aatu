package adapterplugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/sd-strax/reckon/capability"
)

// ProtocolVersion is the plugin protocol version this engine speaks (§4.1). It
// is a single integer bumped only on breaking changes to the RPC surface;
// descriptor-schema evolution rides the descriptors' own versioning, not this
// number. The stability promise: a protocol-v1 adapter keeps working against
// every engine that lists 1 in its supported set.
const ProtocolVersion = 1

// Manifest is the static, spawn-free description of an installed adapter
// (§3). It answers exactly one question — "what is installed here?" — cheaply,
// without launching anything. The summary and config_schema blocks are CLAIMS,
// never authority: the handshake (`describe`, §4.2) is the sole truth on what
// an adapter can actually do. Invariant: manifest for enumeration, handshake
// for truth.
type Manifest struct {
	ManifestVersion  int      `yaml:"manifest_version"`
	Name             string   `yaml:"name"`
	Version          string   `yaml:"version"`
	ProtocolVersions []int    `yaml:"protocol_versions"`
	Class            string   `yaml:"class"` // spec-cased: MCP / NATIVE_API / CUSTOM / SOAR_PLAYBOOK
	Exec             []string `yaml:"exec"`
	Requires         []string `yaml:"requires"`
	Summary          struct {
		Verbs       []string `yaml:"verbs"`
		ActionTypes []string `yaml:"action_types"`
	} `yaml:"summary"`
	ConfigSchema map[string]any `yaml:"config_schema"`
}

// Installed is one adapter directory that parsed cleanly and overlaps the
// engine's protocol version — a candidate for enablement. It is not spawned
// until enabled and demanded (§2, lazy spawn).
type Installed struct {
	Dir      string
	Manifest Manifest
}

// Problem is a malformed or unusable install surfaced by ScanAdapters. A
// malformed install can make an adapter INVISIBLE, never partially visible
// (§3), so a problem is reported (for `reckon check`) and otherwise ignored.
type Problem struct {
	Dir     string
	Message string
}

func (p Problem) String() string { return fmt.Sprintf("%s: %s", p.Dir, p.Message) }

// AdapterClass normalizes the manifest's spec-cased class onto the in-tree
// capability.AdapterClass value. The FIXTURE class is deliberately absent: it
// is compiled-in replay infrastructure, never an out-of-process plugin (§1).
func (m Manifest) AdapterClass() (capability.AdapterClass, error) {
	switch m.Class {
	case "MCP":
		return capability.ClassMCP, nil
	case "NATIVE_API":
		return capability.ClassNativeAPI, nil
	case "CUSTOM":
		return capability.ClassCustom, nil
	case "SOAR_PLAYBOOK":
		return capability.ClassSOARPlaybook, nil
	default:
		return "", fmt.Errorf("unknown or non-plugin class %q (want MCP/NATIVE_API/CUSTOM/SOAR_PLAYBOOK)", m.Class)
	}
}

// validate checks the structural invariants a usable manifest must hold. A
// failure makes the install invisible (a Problem), never partially visible.
func (m Manifest) validate() error {
	if m.ManifestVersion != 1 {
		return fmt.Errorf("unsupported manifest_version %d (want 1)", m.ManifestVersion)
	}
	if m.Name == "" {
		return errors.New("manifest has no name")
	}
	if len(m.Exec) == 0 {
		return errors.New("manifest has no exec")
	}
	if _, err := m.AdapterClass(); err != nil {
		return err
	}
	if !protocolOverlap(m.ProtocolVersions) {
		return fmt.Errorf("no overlapping protocol_versions with engine (engine speaks %d, adapter %v)", ProtocolVersion, m.ProtocolVersions)
	}
	return nil
}

func protocolOverlap(versions []int) bool {
	for _, v := range versions {
		if v == ProtocolVersion {
			return true
		}
	}
	return false
}

// Load reads and validates a single adapter directory's manifest. Unlike
// ScanAdapters it points AT one adapter dir rather than the install root — the
// target shape of `reckon adapter test <path-to-adapter-dir>` (§7).
func Load(dir string) (Installed, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.yaml"))
	if err != nil {
		return Installed{}, fmt.Errorf("read manifest.yaml: %w", err)
	}
	var man Manifest
	if err := yaml.Unmarshal(data, &man); err != nil {
		return Installed{}, fmt.Errorf("parse manifest.yaml: %w", err)
	}
	if err := man.validate(); err != nil {
		return Installed{}, err
	}
	return Installed{Dir: dir, Manifest: man}, nil
}

// ScanAdapters reads the install layout at root (`<data>/adapters/<name>/`,
// §3) and returns the adapters that parsed cleanly, overlap the engine's
// protocol version, and have unique names — plus a Problem for every directory
// that did not. It spawns nothing (the whole point of the manifest). A missing
// root is not an error: no adapters installed is the common case.
//
// The returned map is keyed by manifest name. A duplicate name makes ALL
// claimants of that name a Problem and drops them — an ambiguous install is
// resolved by making it invisible, not by picking a winner.
func ScanAdapters(root string) (map[string]Installed, []Problem) {
	installed := map[string]Installed{}
	var problems []Problem

	entries, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			problems = append(problems, Problem{Dir: root, Message: "read adapters dir: " + err.Error()})
		}
		return installed, problems
	}

	// nameDirs tracks every directory claiming a given name, so a collision can
	// drop all of them.
	nameDirs := map[string][]string{}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		manPath := filepath.Join(dir, "manifest.yaml")
		data, err := os.ReadFile(manPath)
		if err != nil {
			problems = append(problems, Problem{Dir: dir, Message: "read manifest.yaml: " + err.Error()})
			continue
		}
		var man Manifest
		if err := yaml.Unmarshal(data, &man); err != nil {
			problems = append(problems, Problem{Dir: dir, Message: "parse manifest.yaml: " + err.Error()})
			continue
		}
		if err := man.validate(); err != nil {
			problems = append(problems, Problem{Dir: dir, Message: err.Error()})
			continue
		}
		nameDirs[man.Name] = append(nameDirs[man.Name], dir)
		installed[man.Name] = Installed{Dir: dir, Manifest: man}
	}

	// Resolve duplicate names by dropping every claimant and reporting it.
	for name, dirs := range nameDirs {
		if len(dirs) > 1 {
			delete(installed, name)
			sort.Strings(dirs)
			problems = append(problems, Problem{
				Dir:     dirs[0],
				Message: fmt.Sprintf("duplicate adapter name %q claimed by %v — all dropped (§3)", name, dirs),
			})
		}
	}

	return installed, problems
}
