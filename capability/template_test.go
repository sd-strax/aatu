package capability

import (
	"testing"
	"time"
)

func tmplCtx() map[string]any {
	return map[string]any{
		"entity": map[string]any{
			"host":    map[string]any{"hostname": "WIN-DC01"},
			"process": map[string]any{"pid": "4242"},
		},
		"window": map[string]any{"from": time.Date(2026, 4, 20, 14, 0, 0, 0, time.UTC)},
		"verb":   "get_process_ancestry",
	}
}

func TestTemplateSingleTypedValue(t *testing.T) {
	// A lone expression with an int-typed source yields the int, not a string.
	tp, err := parseTemplate("${entity.process.pid | int}")
	if err != nil {
		t.Fatal(err)
	}
	v, st, err := tp.render(tmplCtx())
	if err != nil || st != statusOK {
		t.Fatalf("render: v=%v st=%v err=%v", v, st, err)
	}
	if v != 4242 {
		t.Errorf("got %#v; want int 4242", v)
	}
}

func TestTemplateTransforms(t *testing.T) {
	cases := map[string]any{
		"${entity.host.hostname | lower}": "win-dc01",
		"${entity.host.hostname | upper}": "WIN-DC01",
		"${window.from | iso8601}":        "2026-04-20T14:00:00Z",
	}
	for tmpl, want := range cases {
		tp, err := parseTemplate(tmpl)
		if err != nil {
			t.Fatalf("%s: parse: %v", tmpl, err)
		}
		v, _, err := tp.render(tmplCtx())
		if err != nil {
			t.Fatalf("%s: render: %v", tmpl, err)
		}
		if v != want {
			t.Errorf("%s = %#v; want %#v", tmpl, v, want)
		}
	}
}

func TestTemplateOptionalDefaultRequired(t *testing.T) {
	ctx := tmplCtx()

	// Required missing → not applicable.
	tp, _ := parseTemplate("${entity.host.external_id}")
	if _, st, _ := tp.render(ctx); st != statusNotApplicable {
		t.Errorf("required missing: status %v; want NotApplicable", st)
	}

	// Optional missing → omit.
	tp, _ = parseTemplate("${entity.host.external_id?}")
	if _, st, _ := tp.render(ctx); st != statusOmit {
		t.Errorf("optional missing: status %v; want Omit", st)
	}

	// Default → literal.
	tp, _ = parseTemplate(`${entity.host.external_id ?? "unknown"}`)
	v, st, _ := tp.render(ctx)
	if st != statusOK || v != "unknown" {
		t.Errorf("default: v=%v st=%v; want ok/unknown", v, st)
	}
}

func TestTemplateMixedText(t *testing.T) {
	tp, err := parseTemplate("host=${entity.host.hostname | lower};verb=${verb}")
	if err != nil {
		t.Fatal(err)
	}
	v, st, err := tp.render(tmplCtx())
	if err != nil || st != statusOK {
		t.Fatalf("render: %v %v", st, err)
	}
	if v != "host=win-dc01;verb=get_process_ancestry" {
		t.Errorf("mixed render = %q", v)
	}
}

func TestTemplateUnknownTransformRejected(t *testing.T) {
	if _, err := parseTemplate("${entity.host.hostname | bogus}"); err == nil {
		t.Error("unknown transform accepted; want parse error")
	}
}

func TestRenderParamsNestedAndApplicability(t *testing.T) {
	ctx := tmplCtx()

	// Nested map with an optional missing leaf: the leaf is dropped, the binding
	// stays applicable.
	params := map[string]any{
		"filters": map[string]any{
			"host": "${entity.host.hostname | lower}",
			"tag":  "${entity.host.missing?}",
		},
		"literal": 5,
	}
	out, applicable, err := renderParams(params, ctx)
	if err != nil || !applicable {
		t.Fatalf("renderParams: applicable=%v err=%v", applicable, err)
	}
	filters := out["filters"].(map[string]any)
	if filters["host"] != "win-dc01" {
		t.Errorf("filters.host = %v; want win-dc01", filters["host"])
	}
	if _, present := filters["tag"]; present {
		t.Error("optional-missing tag should have been omitted")
	}
	if out["literal"] != 5 {
		t.Errorf("literal passthrough = %v; want 5", out["literal"])
	}

	// A required missing path anywhere makes the whole binding not applicable.
	if _, applicable, _ := renderParams(map[string]any{"d": "${entity.host.external_id}"}, ctx); applicable {
		t.Error("required-missing binding reported applicable")
	}
}
