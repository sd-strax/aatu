package capability

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Enablement plumbing for the conversational surface (11 §5.1): the tenant
// config FILE stays the single source of truth, and everything here is sugar
// that edits it — diffable, reviewable, identical whether a human or the
// workbench widget wrote it. The model is never an author: these functions are
// reached only from the human-confirmed endpoint.

// AdapterConfigSchema returns the JSON-schema-shaped instance-config
// descriptor for an adapter class (11 §4.3): plain JSON Schema whose
// `description` strings become the form's prompt text, plus the one reckon
// extension — `x-secret` marks the fields whose values must be secret
// REFERENCES (keychain:// / env:// / vault://), never literals. v0 ships only
// the fixture class; out-of-process adapters bring their own schema via
// `describe` in Phase E.
func AdapterConfigSchema(class AdapterClass) map[string]any {
	if class != ClassFixture {
		return nil
	}
	return map[string]any{
		"type":     "object",
		"required": []any{"scenario"},
		"properties": map[string]any{
			"scenario": map[string]any{
				"type":        "string",
				"description": "Fixture scenario directory to replay (under the fixtures root), e.g. lateral-movement-via-rdp",
			},
		},
	}
}

// UpdateAdapterEnablement rewrites ONE adapter stanza in the tenant config
// file: the enabled flag plus any provided config fields (for the fixture
// class, `scenario`). The rest of the document — other stanzas, comments,
// ordering — survives via a yaml.Node round-trip, because the file is the
// artifact operators diff and review. The adapter must already exist:
// enablement toggles installed capability, it never installs (11 §6.1).
// The write is atomic (temp file + rename), so a crash never leaves a
// half-written config for the next boot to fail on.
func UpdateAdapterEnablement(path, adapter string, enabled bool, fields map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read tenant config %s: %w", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse tenant config %s: %w", path, err)
	}
	if len(doc.Content) == 0 {
		return fmt.Errorf("tenant config %s is empty", path)
	}
	root := doc.Content[0]
	adaptersNode := mappingValue(root, "adapters")
	if adaptersNode == nil {
		return fmt.Errorf("tenant config %s has no adapters section", path)
	}
	stanza := mappingValue(adaptersNode, adapter)
	if stanza == nil {
		return fmt.Errorf("adapter %q is not installed in the tenant config (enablement never installs — 11 §6.1)", adapter)
	}

	setMappingScalar(stanza, "enabled", fmt.Sprintf("%t", enabled), "!!bool")
	for k, v := range fields {
		setMappingScalar(stanza, k, v, "!!str")
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("render tenant config: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".enablement-*")
	if err != nil {
		return fmt.Errorf("stage tenant config: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write tenant config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close tenant config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace tenant config: %w", err)
	}
	return nil
}

// mappingValue returns the value node for a key in a YAML mapping, or nil.
func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

// setMappingScalar sets key to a scalar value in a mapping node, appending the
// pair if the key is absent.
func setMappingScalar(mapping *yaml.Node, key, value, tag string) {
	if v := mappingValue(mapping, key); v != nil {
		v.SetString(value)
		v.Tag = tag
		return
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value},
	)
}
