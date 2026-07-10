package capability

// This file exposes the read-side templating primitives to the write-side
// action resolver (design/08 §4), which shares one templating engine rather
// than duplicating it. The internals stay unexported; these are the seams the
// action package depends on.

// RenderParams renders a binding's parameter template against ctx (§3.3). A
// required-missing path makes the binding not applicable (applicable=false); an
// optional-missing path drops its key.
func RenderParams(params map[string]any, ctx map[string]any) (map[string]any, bool, error) {
	return renderParams(params, ctx)
}

// ValidateParamTemplates compiles every template in a parameter map, surfacing
// syntax and unknown-transform errors at config-load time (§3.3.4).
func ValidateParamTemplates(params map[string]any) error {
	return validateParams(params)
}

// LookupPath resolves a dotted path ("target.resolved_identifier") into a nested
// map, falling back to a direct flat key of the same name.
func LookupPath(m map[string]any, path string) (any, bool) {
	return lookupPath(m, path)
}
