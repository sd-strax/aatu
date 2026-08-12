package substrate

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestHashV1Golden pins the §3 one-way door against an independently
// hand-written canonical form: keys sorted (body, tags, title), tags sorted
// and deduplicated, absent optionals omitted entirely. If this test breaks,
// the hash scheme changed — which is forbidden without a new hash_version.
func TestHashV1Golden(t *testing.T) {
	got, err := hashContent(Content{
		Title: "Ransomware triage",
		Body:  "Isolate first.",
		Tags:  []string{"ransomware", "edr", "ransomware"},
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"body":"Isolate first.","tags":["edr","ransomware"],"title":"Ransomware triage"}`
	want := sha256.Sum256([]byte(canonical))
	if string(got) != hex.EncodeToString(want[:]) {
		t.Fatalf("hash drifted from the v1 canonical form:\n got %s\nwant sha256(%s)", got, canonical)
	}
}

func TestHashCoversContentOnly(t *testing.T) {
	base := Content{Title: "T", Body: "B", Tags: []string{"x"}}
	h1, err := hashContent(base)
	if err != nil {
		t.Fatal(err)
	}

	// Tag order and duplication never change the hash.
	h2, _ := hashContent(Content{Title: "T", Body: "B", Tags: []string{"x", "x"}})
	if h1 != h2 {
		t.Error("duplicate tags changed the hash")
	}

	// Absent optionals are omitted — adding one must change the hash.
	withAdvice, _ := hashContent(Content{Title: "T", Body: "B", Tags: []string{"x"}, Advice: "isolate"})
	if withAdvice == h1 {
		t.Error("advice did not contribute to the hash")
	}
	withMeta, _ := hashContent(Content{Title: "T", Body: "B", Tags: []string{"x"}, Meta: map[string]any{"sev": 3}})
	if withMeta == h1 {
		t.Error("meta did not contribute to the hash")
	}
}

func TestHashMetaStable(t *testing.T) {
	// Arbitrary JSON in meta (nested objects, fractional numbers) must hash
	// identically across calls — RFC 8785 owns number and key canonicalization.
	m := map[string]any{"score": 0.5, "nested": map[string]any{"b": 1, "a": "z"}, "list": []any{1, 2.25}}
	h1, err := hashContent(Content{Title: "T", Body: "B", Meta: m})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := hashContent(Content{Title: "T", Body: "B", Meta: map[string]any{"list": []any{1, 2.25}, "nested": map[string]any{"a": "z", "b": 1}, "score": 0.5}})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("meta canonicalization unstable: %s vs %s", h1, h2)
	}
}
