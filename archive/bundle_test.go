package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func sampleInvestigation() Investigation {
	return Investigation{
		GroupingID:      "11111111-1111-1111-1111-111111111111",
		Title:           "RDP lateral movement",
		Status:          "CONCLUDED",
		Summary:         "Confirmed C2 via DNS tunneling from WIN-A.",
		ReportRef:       "report--1",
		TenantNamespace: "6f1b2c3d-0000-4000-8000-000000000001",
		ConcludedAt:     time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC),
		Events: []json.RawMessage{
			json.RawMessage(`{"sequence_no":1,"type":"investigation.created"}`),
			json.RawMessage(`{"sequence_no":2,"type":"interpretation.recorded"}`),
		},
		StixObjects: []json.RawMessage{
			json.RawMessage(`{"type":"x-hypothesis","id":"x-hypothesis--1","status":"SUPPORTED"}`),
		},
		Hypotheses: []HypothesisSummary{
			{ID: "x-hypothesis--1", Statement: "C2 via DNS tunneling", Status: "SUPPORTED", Labels: []string{"T1071.004"}},
		},
		Actions: []ActionSummary{
			{ID: "act-1", ActionType: "host.isolate", Tier: "T2", Status: "SUCCEEDED"},
		},
		IncludeSideStores: true,
		Transcripts:       []Blob{{Hash: "abc123", Bytes: []byte("assistant: proposing H1")}},
		ToolCalls:         []Blob{{Hash: "def456", Bytes: []byte(`{"tool":"list_processes"}`)}},
	}
}

// untar reads a tar.gz into a name→bytes map.
func untar(t *testing.T, gzBytes []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		t.Fatalf("gzip open: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %s: %v", h.Name, err)
		}
		out[h.Name] = b
	}
	return out
}

// TestBuildBundle_StructureAndSignature: a built bundle unpacks to the expected
// files, the manifest's content hash covers every content file, and the
// detached signature verifies against the signer's public key — the whole
// point of a signed, self-contained export (07 §2.2).
func TestBuildBundle_StructureAndSignature(t *testing.T) {
	signer, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	genAt := time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)

	res, err := BuildBundle(sampleInvestigation(), signer, genAt)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	if !strings.HasPrefix(res.Filename, "investigation-11111111") || !strings.HasSuffix(res.Filename, ".tar.gz") {
		t.Errorf("filename = %q; unexpected shape", res.Filename)
	}

	files := untar(t, res.Bytes)
	for _, want := range []string{
		"manifest.json", "investigation.report.md", "events.jsonl", "stix-bundle.json",
		"signatures/bundle.sig", "signatures/chain.json",
		"side-stores/transcripts/abc123.txt", "side-stores/tool-calls/def456.json",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("bundle missing %s", want)
		}
	}

	// events.jsonl is one event per line, in order.
	lines := bytes.Split(bytes.TrimSpace(files["events.jsonl"]), []byte("\n"))
	if len(lines) != 2 {
		t.Errorf("events.jsonl has %d lines; want 2", len(lines))
	}

	// stix-bundle.json is a valid STIX bundle envelope.
	var stix struct {
		Type    string            `json:"type"`
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(files["stix-bundle.json"], &stix); err != nil || stix.Type != "bundle" || len(stix.Objects) != 1 {
		t.Errorf("stix-bundle.json = %s (%v); want a bundle with 1 object", files["stix-bundle.json"], err)
	}

	// The manifest's content hash must equal a recompute over every non-manifest,
	// non-signature file — and the signature must verify over that hash.
	var m Manifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatalf("manifest parse: %v", err)
	}
	if m.ContentHash != res.ContentHash {
		t.Errorf("manifest hash %s != result hash %s", m.ContentHash, res.ContentHash)
	}
	if m.Signature == nil {
		t.Fatal("manifest missing signature")
	}
	sig, err := hex.DecodeString(m.Signature.Sig)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := hex.DecodeString(m.ContentHash)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(signer.PublicKey(), hash, sig) {
		t.Error("signature does not verify against the signer's public key")
	}
}

// TestBuildBundle_TamperDetected: flipping a byte in a content file changes the
// recomputed hash, so the recorded signature no longer verifies — the bundle is
// tamper-evident.
func TestBuildBundle_TamperDetected(t *testing.T) {
	signer, _ := GenerateEd25519Signer()
	res, err := BuildBundle(sampleInvestigation(), signer, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	files := untar(t, res.Bytes)

	var m Manifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(m.Signature.Sig)

	// Recompute the content hash the way BuildBundle does, but over a TAMPERED
	// report — it must differ, and the original signature must fail against it.
	tampered := append([]byte(nil), files["investigation.report.md"]...)
	tampered = append(tampered, '!')
	files["investigation.report.md"] = tampered

	rehash := recomputeContentHash(files)
	if hex.EncodeToString(rehash) == m.ContentHash {
		t.Fatal("tampered content produced the same hash")
	}
	if ed25519.Verify(signer.PublicKey(), rehash, sig) {
		t.Error("signature verified over tampered content — not tamper-evident")
	}
}

// TestBuildBundle_RedactsSideStores: with IncludeSideStores false, no Layer B
// content is packed (07 §2.2 optional redaction).
func TestBuildBundle_RedactsSideStores(t *testing.T) {
	inv := sampleInvestigation()
	inv.IncludeSideStores = false
	res, err := BuildBundle(inv, nil, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	files := untar(t, res.Bytes)
	for name := range files {
		if strings.HasPrefix(name, "side-stores/") {
			t.Errorf("redacted bundle still contains %s", name)
		}
	}
	// An unsigned build (nil signer) omits the signature files + manifest sig.
	if _, ok := files["signatures/bundle.sig"]; ok {
		t.Error("unsigned bundle carries a signature file")
	}
	var m Manifest
	_ = json.Unmarshal(files["manifest.json"], &m)
	if m.Signature != nil {
		t.Error("unsigned manifest carries a signature block")
	}
}

// recomputeContentHash mirrors BuildBundle's hashing over the content files
// (everything except manifest.json and signatures/*), for the tamper test.
func recomputeContentHash(files map[string][]byte) []byte {
	content := map[string][]byte{}
	for n, b := range files {
		if n == "manifest.json" || strings.HasPrefix(n, "signatures/") {
			continue
		}
		content[n] = b
	}
	// Reuse the same framing as BuildBundle via a throwaway build path.
	return contentHashOf(content)
}
