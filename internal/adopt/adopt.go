// Package adopt is the shared "adopt + enable" primitive (design/11 §5): it turns
// an adapter's describe output into a tenant-config enablement fragment and
// merges it into the tenant config FILE — the single source of truth that every
// surface edits (§5.1). It is deliberately front-end-agnostic: the CLI `reckon
// adapter setup` calls it now, and the workbench §5.1 conversational form calls
// the same Plan/Apply later. Only the trigger differs.
//
// A Plan is computed from the adapter's `describe` (its proposed default
// bindings) plus the operations/action-types the operator chose and the
// non-secret instance config. Apply merges it into the config with a yaml.Node
// round-trip, so comments, ordering, and other adapters survive.
package adopt

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/sd-strax/reckon/internal/adapterplugin"
)

// Plan is the config fragment to merge for one adapter instance. Nil sides
// (no reads / no writes enabled) are skipped by Apply.
type Plan struct {
	Instance string
	// ReadAdapter is the adapters.<instance> stanza; ReadBindings is verb → stanzas.
	ReadAdapter  map[string]any
	ReadBindings map[string][]map[string]any
	// WriteAdapter is the action_adapters.<instance> stanza; WriteBindings is
	// action_type → stanzas.
	WriteAdapter  map[string]any
	WriteBindings map[string][]map[string]any
	// Summary is what the plan enables, for operator confirmation/output.
	Summary Summary
}

// Summary lists what a plan enables.
type Summary struct {
	Verbs       []string
	ActionTypes []string
}

// PlanFrom computes an adoption plan from an adapter's describe output. class is
// the adapter's manifest class ("mcp", "native_api", …); install is the
// installed-adapter name; config is the non-secret instance config (org_url,
// client_id, …) or secret references. enableReadOps selects which read
// operations to bind (their verbs come from describe); enableActionTypes selects
// which write action-types to bind — writes are per-op explicit (§5), never a
// wildcard.
func PlanFrom(d *adapterplugin.DescribeResult, instance, install, class string, config map[string]string, enableReadOps, enableActionTypes []string) Plan {
	p := Plan{Instance: instance, ReadBindings: map[string][]map[string]any{}, WriteBindings: map[string][]map[string]any{}}
	readOps := toSet(enableReadOps)
	actTypes := toSet(enableActionTypes)
	cfg := configMap(config)

	var reads []string
	verbs := map[string]bool{}
	for _, rb := range d.DefaultReadBindings {
		if !readOps[rb.Operation] {
			continue
		}
		reads = appendUnique(reads, rb.Operation)
		st := bindingStanza(instance, rb.Operation, rb.Priority, rb.Params)
		p.ReadBindings[rb.Verb] = append(p.ReadBindings[rb.Verb], st)
		verbs[rb.Verb] = true
	}
	if len(reads) > 0 {
		p.ReadAdapter = adapterStanza(class, install, "reads", reads, cfg)
	}
	p.Summary.Verbs = sortedKeys(verbs)

	var actions []string
	ats := map[string]bool{}
	for _, wb := range d.DefaultWriteBindings {
		if !actTypes[wb.ActionType] {
			continue
		}
		actions = appendUnique(actions, wb.Operation)
		st := bindingStanza(instance, wb.Operation, wb.Priority, wb.Params)
		st["action_type"] = wb.ActionType
		p.WriteBindings[wb.ActionType] = append(p.WriteBindings[wb.ActionType], st)
		ats[wb.ActionType] = true
	}
	if len(actions) > 0 {
		p.WriteAdapter = adapterStanza(class, install, "actions", actions, cfg)
	}
	p.Summary.ActionTypes = sortedKeys(ats)
	return p
}

// Apply merges a Plan into the tenant config file at path (created if absent),
// preserving existing content, and writes it atomically. The four sections
// (adapters/bindings/action_adapters/action_bindings) are created as needed.
func Apply(path string, p Plan) error {
	var doc yaml.Node
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parse tenant config %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read tenant config %s: %w", path, err)
	}
	root := docRoot(&doc)

	if p.ReadAdapter != nil {
		if err := setChild(section(root, "adapters"), p.Instance, p.ReadAdapter); err != nil {
			return err
		}
		for verb, sts := range p.ReadBindings {
			if err := setChild(section(root, "bindings"), verb, sts); err != nil {
				return err
			}
		}
	}
	if p.WriteAdapter != nil {
		if err := setChild(section(root, "action_adapters"), p.Instance, p.WriteAdapter); err != nil {
			return err
		}
		for at, sts := range p.WriteBindings {
			if err := setChild(section(root, "action_bindings"), at, sts); err != nil {
				return err
			}
		}
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("render tenant config: %w", err)
	}
	return atomicWrite(path, out)
}

// --- yaml.Node helpers ---

// docRoot returns the mapping node at the document root, initializing an empty
// document into a mapping.
func docRoot(doc *yaml.Node) *yaml.Node {
	if len(doc.Content) == 0 {
		root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{root}
		return root
	}
	return doc.Content[0]
}

// section returns the mapping node for a top-level key, creating it if absent.
func section(root *yaml.Node, key string) *yaml.Node {
	if v := mappingValue(root, key); v != nil {
		return v
	}
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, node)
	return node
}

// setChild sets parent[key] = value (marshaled to a node), replacing an existing
// key or appending a new one.
func setChild(parent *yaml.Node, key string, value any) error {
	node, err := toNode(value)
	if err != nil {
		return err
	}
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			parent.Content[i+1] = node
			return nil
		}
	}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, node)
	return nil
}

// toNode marshals a Go value into a yaml content node.
func toNode(v any) (*yaml.Node, error) {
	b, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null"}, nil
	}
	return doc.Content[0], nil
}

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

func atomicWrite(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".adopt-*")
	if err != nil {
		return fmt.Errorf("stage tenant config: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write tenant config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("replace tenant config: %w", err)
	}
	return nil
}

// --- stanza builders ---

func adapterStanza(class, install, opsKey string, ops []string, cfg map[string]any) map[string]any {
	st := map[string]any{"class": class, "enabled": true, "adapter": install, opsKey: ops}
	if cfg != nil {
		st["config"] = cfg
	}
	return st
}

func bindingStanza(instance, operation string, priority int, params map[string]any) map[string]any {
	st := map[string]any{"adapter": instance, "operation": operation, "priority": orDef(priority, 100)}
	if len(params) > 0 {
		st["params"] = params
	}
	return st
}

func configMap(config map[string]string) map[string]any {
	if len(config) == 0 {
		return nil
	}
	out := make(map[string]any, len(config))
	for k, v := range config {
		out[k] = v
	}
	return out
}

func toSet(vals []string) map[string]bool {
	s := make(map[string]bool, len(vals))
	for _, v := range vals {
		s[v] = true
	}
	return s
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orDef(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
