package action

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// exprRe captures the body of each ${...} template expression.
var exprRe = regexp.MustCompile(`\$\{([^}]*)\}`)

// paramNameRe pulls the input name out of a "parameters.<name>" head.
var paramNameRe = regexp.MustCompile(`^parameters\.([A-Za-z0-9_]+)`)

// ValidateBindingParams cross-checks every binding's ${parameters.X} references
// against the action catalog's DECLARED inputs for that action type. It exists
// because a binding that references an input the descriptor never declares is
// silently never-applicable at dispatch: the resolver's RenderParams rejects the
// missing required path and falls through to a lower-priority binding (e.g. the
// demo fixture) — a routing bug that surfaces nowhere until the wrong tool acts.
// Surfacing it at load/author time turns that silent fallthrough into a loud,
// actionable message.
//
// The catalog is the authority on what the AGENT emits (04 §2), so a binding
// must speak the catalog's vocabulary, not the tool's own field names — the
// tool's field is the map KEY; the ${parameters.X} template is the canonical
// input. Action types with no descriptor, or a descriptor that declares no
// inputs, are skipped (nothing to validate against). Returns one message per
// mismatch, sorted; empty when every reference is a declared input.
func ValidateBindingParams(bindings map[string][]ActionBinding, catalog *ActionCatalog) []string {
	if catalog == nil {
		return nil
	}
	var problems []string
	for actionType, bs := range bindings {
		desc, ok := catalog.Descriptor(actionType)
		if !ok || len(desc.Inputs) == 0 {
			continue
		}
		declared := make(map[string]bool, len(desc.Inputs))
		names := make([]string, 0, len(desc.Inputs))
		for _, in := range desc.Inputs {
			declared[in.Name] = true
			names = append(names, in.Name)
		}
		sort.Strings(names)
		for _, b := range bs {
			for _, ref := range bindingParamRefs(b.Params) {
				if !declared[ref] {
					problems = append(problems, fmt.Sprintf(
						"binding %s→%s references parameters.%s, which is not a declared input of %s (declared inputs: %v)",
						actionType, b.Adapter, ref, actionType, names))
				}
			}
		}
	}
	sort.Strings(problems)
	return problems
}

// bindingParamRefs returns the distinct REQUIRED ${parameters.X} input names in
// a binding's templates, recursing nested maps/slices. Only required refs are
// returned: an optional (`X?`) or defaulted (`X ?? d`) ref to an undeclared
// input is harmless (it omits or defaults), so flagging it would be a false
// positive (e.g. a servicenow `urgency ?? 3 - Low` for a field the engine
// doesn't model). A required ref to an undeclared input is the real bug — it
// makes the whole binding never-applicable.
func bindingParamRefs(params map[string]any) []string {
	seen := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			for _, m := range exprRe.FindAllStringSubmatch(t, -1) {
				if name, required := requiredParamRef(m[1]); required {
					seen[name] = true
				}
			}
		case map[string]any:
			for _, x := range t {
				walk(x)
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		}
	}
	for _, v := range params {
		walk(v)
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// requiredParamRef classifies one ${...} expression body. It returns the
// parameters.<name> it references and whether that reference is REQUIRED —
// i.e. not optional (`name?`) and not defaulted (`name ?? default`), the only
// case where a missing value rejects the binding (03 §3.3.4). Non-parameters
// refs (target.*, action) return required=false.
func requiredParamRef(body string) (string, bool) {
	head := body
	if i := strings.IndexByte(head, '|'); i >= 0 { // strip transforms
		head = head[:i]
	}
	head = strings.TrimSpace(head)
	m := paramNameRe.FindStringSubmatch(head)
	if m == nil {
		return "", false // not a parameters.* reference
	}
	name := m[1]
	rest := strings.TrimSpace(head[len(m[0]):])
	if strings.HasPrefix(rest, "??") || strings.HasPrefix(rest, "?") {
		return name, false // optional or defaulted — a missing value is fine
	}
	return name, true
}
