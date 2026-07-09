package capability

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Parameter templating (§3.3): string substitution with typed-path references
// and a sealed-but-extensible function set. NOT a full expression language — no
// conditionals, loops, or arbitrary code. Syntax:
//
//	${entity.host.hostname}            required — missing rejects the binding
//	${entity.host.hostname?}           optional — missing omits the param
//	${entity.host.hostname ?? "x"}     default — missing substitutes the literal
//	${window.from | iso8601}           transforms piped left to right
//
// Path roots: entity, window, tenant, verb. Templates are validated at
// config-load (unknown transforms reject); rendering is pure.

// renderStatus is the outcome of rendering one parameter value.
type renderStatus int

const (
	statusOK            renderStatus = iota // value produced
	statusOmit                              // optional path missing — drop this key
	statusNotApplicable                     // required path missing — reject the binding
)

// transformFn maps a value through one named transform.
type transformFn func(any) (any, error)

// builtinTransforms is the sealed function set (§3.3.2). Adapter-registered
// transforms (splunk_quote, kql_quote, …) are a Phase E extension.
var builtinTransforms = map[string]transformFn{
	"upper":    func(v any) (any, error) { return strings.ToUpper(toStr(v)), nil },
	"lower":    func(v any) (any, error) { return strings.ToLower(toStr(v)), nil },
	"trim":     func(v any) (any, error) { return strings.TrimSpace(toStr(v)), nil },
	"string":   func(v any) (any, error) { return toStr(v), nil },
	"int":      transformInt,
	"bool":     transformBool,
	"iso8601":  func(v any) (any, error) { return asTime(v).UTC().Format(time.RFC3339), nil },
	"epoch_ms": func(v any) (any, error) { return asTime(v).UnixMilli(), nil },
	"epoch_s":  func(v any) (any, error) { return asTime(v).Unix(), nil },
}

// templateExpr is one ${...} reference.
type templateExpr struct {
	path       string
	optional   bool
	hasDefault bool
	defaultVal string
	transforms []string
}

// templatePart is either literal text (expr == nil) or an expression.
type templatePart struct {
	literal string
	expr    *templateExpr
}

// template is a compiled parameter string. single is true when it is exactly
// one expression with no surrounding text, so it can yield a typed value rather
// than a string.
type template struct {
	parts  []templatePart
	single bool
}

// parseTemplate compiles s, validating that every referenced transform exists.
func parseTemplate(s string) (*template, error) {
	t := &template{}
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			if s != "" {
				t.parts = append(t.parts, templatePart{literal: s})
			}
			break
		}
		if i > 0 {
			t.parts = append(t.parts, templatePart{literal: s[:i]})
		}
		end := strings.Index(s[i:], "}")
		if end < 0 {
			return nil, fmt.Errorf("unterminated template expression in %q", s)
		}
		inner := s[i+2 : i+end]
		expr, err := parseExpr(inner)
		if err != nil {
			return nil, err
		}
		t.parts = append(t.parts, templatePart{expr: expr})
		s = s[i+end+1:]
	}
	t.single = len(t.parts) == 1 && t.parts[0].expr != nil
	return t, nil
}

// parseExpr parses "path [?|?? default] [| transform]*".
func parseExpr(s string) (*templateExpr, error) {
	e := &templateExpr{}

	// Transforms first (split on '|'), then the path/default head.
	segs := strings.Split(s, "|")
	head := strings.TrimSpace(segs[0])
	for _, seg := range segs[1:] {
		name := strings.TrimSpace(seg)
		if _, ok := builtinTransforms[name]; !ok {
			return nil, fmt.Errorf("unknown transform %q", name)
		}
		e.transforms = append(e.transforms, name)
	}

	// Default: path ?? "literal"
	if idx := strings.Index(head, "??"); idx >= 0 {
		e.path = strings.TrimSpace(head[:idx])
		e.hasDefault = true
		e.defaultVal = strings.Trim(strings.TrimSpace(head[idx+2:]), `"`)
		return e, nil
	}
	// Optional: path?
	if strings.HasSuffix(head, "?") {
		e.optional = true
		head = strings.TrimSpace(strings.TrimSuffix(head, "?"))
	}
	e.path = head
	if e.path == "" {
		return nil, fmt.Errorf("empty template path")
	}
	return e, nil
}

// resolve looks up the expression's path in ctx, applies its transforms, and
// returns (value, present). A missing path with a default yields the default;
// a missing path without one yields present=false.
func (e *templateExpr) resolve(ctx map[string]any) (any, bool, error) {
	v, ok := lookupPath(ctx, e.path)
	if !ok || v == nil || v == "" {
		if e.hasDefault {
			return e.defaultVal, true, nil
		}
		return nil, false, nil
	}
	var err error
	for _, name := range e.transforms {
		if v, err = builtinTransforms[name](v); err != nil {
			return nil, false, fmt.Errorf("transform %s: %w", name, err)
		}
	}
	return v, true, nil
}

// render evaluates the template against ctx, returning the value and a status
// (§3.3.4): a required missing path is statusNotApplicable; an optional missing
// path is statusOmit.
func (t *template) render(ctx map[string]any) (any, renderStatus, error) {
	if t.single {
		e := t.parts[0].expr
		v, present, err := e.resolve(ctx)
		if err != nil {
			return nil, statusOK, err
		}
		if !present {
			if e.optional {
				return nil, statusOmit, nil
			}
			return nil, statusNotApplicable, nil
		}
		return v, statusOK, nil
	}

	var sb strings.Builder
	for _, p := range t.parts {
		if p.expr == nil {
			sb.WriteString(p.literal)
			continue
		}
		v, present, err := p.expr.resolve(ctx)
		if err != nil {
			return nil, statusOK, err
		}
		if !present {
			if p.expr.optional || p.expr.hasDefault {
				continue // omit this segment
			}
			return nil, statusNotApplicable, nil
		}
		sb.WriteString(toStr(v))
	}
	return sb.String(), statusOK, nil
}

// renderValue renders one parameter value (string template, nested map, slice,
// or literal) against ctx.
func renderValue(v any, ctx map[string]any) (any, renderStatus, error) {
	switch val := v.(type) {
	case string:
		t, err := parseTemplate(val)
		if err != nil {
			return nil, statusOK, err
		}
		return t.render(ctx)
	case map[string]any:
		out, applicable, err := renderParams(val, ctx)
		if err != nil {
			return nil, statusOK, err
		}
		if !applicable {
			return nil, statusNotApplicable, nil
		}
		return out, statusOK, nil
	case []any:
		out := make([]any, 0, len(val))
		for _, item := range val {
			rv, st, err := renderValue(item, ctx)
			if err != nil {
				return nil, statusOK, err
			}
			if st == statusNotApplicable {
				return nil, statusNotApplicable, nil
			}
			if st == statusOmit {
				continue
			}
			out = append(out, rv)
		}
		return out, statusOK, nil
	default:
		return v, statusOK, nil // numeric/bool literals pass through
	}
}

// renderParams renders a binding's parameter map. A required missing path makes
// the whole binding not applicable (applicable=false); optional missing paths
// drop their keys.
func renderParams(params map[string]any, ctx map[string]any) (map[string]any, bool, error) {
	out := make(map[string]any, len(params))
	for k, v := range params {
		rv, st, err := renderValue(v, ctx)
		if err != nil {
			return nil, false, err
		}
		switch st {
		case statusNotApplicable:
			return nil, false, nil
		case statusOmit:
			continue
		default:
			out[k] = rv
		}
	}
	return out, true, nil
}

// --- transform helpers ------------------------------------------------------

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func transformInt(v any) (any, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		return int(n), nil
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return nil, fmt.Errorf("not an int: %q", n)
		}
		return i, nil
	default:
		return nil, fmt.Errorf("cannot coerce %T to int", v)
	}
}

func transformBool(v any) (any, error) {
	switch b := v.(type) {
	case bool:
		return b, nil
	case string:
		return strconv.ParseBool(strings.TrimSpace(b))
	default:
		return nil, fmt.Errorf("cannot coerce %T to bool", v)
	}
}

// asTime coerces a value to time.Time, accepting time.Time, RFC3339 strings, and
// epoch-millisecond numbers. Returns the zero time otherwise.
func asTime(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t
	case string:
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			return parsed
		}
	case float64:
		return time.UnixMilli(int64(t))
	case int64:
		return time.UnixMilli(t)
	}
	return time.Time{}
}
