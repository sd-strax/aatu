package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
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

	// Full verification, exactly as a third party would do it (see Manifest doc):
	// (1) the detached signature verifies over sha256(manifest.json as shipped);
	// (2) the manifest's ContentHash equals a recompute over the listed files.
	var m Manifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatalf("manifest parse: %v", err)
	}
	if m.ContentHash != res.ContentHash {
		t.Errorf("manifest hash %s != result hash %s", m.ContentHash, res.ContentHash)
	}
	sig, err := hex.DecodeString(string(files["signatures/bundle.sig"]))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(files["manifest.json"])
	if !ed25519.Verify(signer.PublicKey(), digest[:], sig) {
		t.Error("signature does not verify over the manifest bytes")
	}
	content := map[string][]byte{}
	for _, name := range m.Files {
		body, ok := files[name]
		if !ok {
			t.Fatalf("manifest lists %s but the bundle lacks it", name)
		}
		content[name] = body
	}
	if hex.EncodeToString(contentHashOf(content)) != m.ContentHash {
		t.Error("recomputed content hash does not match the manifest")
	}
	// chain.json carries the same signature + the signing key id.
	var chain Chain
	if err := json.Unmarshal(files["signatures/chain.json"], &chain); err != nil {
		t.Fatal(err)
	}
	if chain.KeyID != signer.KeyID() || chain.Sig != string(files["signatures/bundle.sig"]) {
		t.Errorf("chain = %+v; want key %s and the detached sig", chain, signer.KeyID())
	}
}

// TestContentHash_FramingInjective: the length-prefixed framing must give
// distinct digests to distinct file sets — the 1.0 framing collided on exactly
// this pair, letting file boundaries be restructured under a valid signature.
func TestContentHash_FramingInjective(t *testing.T) {
	a := contentHashOf(map[string][]byte{"a": []byte("x\nb\ny")})
	b := contentHashOf(map[string][]byte{"a": []byte("x"), "b": []byte("y")})
	if bytes.Equal(a, b) {
		t.Fatal("distinct file sets produced the same content hash (malleable framing)")
	}
}

// TestBuildBundle_TamperDetected: both tamper directions are caught. Flipping a
// byte in a content file breaks the manifest's content hash (step 2 of
// verification); flipping a byte in the manifest — including its metadata
// fields, which sit INSIDE the signed envelope — breaks the signature (step 1).
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
	sig, _ := hex.DecodeString(string(files["signatures/bundle.sig"]))

	// (a) Content tamper: the recomputed hash over the listed files diverges.
	tampered := map[string][]byte{}
	for _, name := range m.Files {
		tampered[name] = files[name]
	}
	tampered["investigation.report.md"] = append(append([]byte(nil), tampered["investigation.report.md"]...), '!')
	if hex.EncodeToString(contentHashOf(tampered)) == m.ContentHash {
		t.Fatal("tampered content produced the same hash")
	}

	// (b) Metadata tamper: re-attributing the manifest (e.g. its grouping id)
	// changes the manifest bytes, so the signature over them fails.
	badManifest := bytes.Replace(files["manifest.json"],
		[]byte("11111111-1111-1111-1111-111111111111"),
		[]byte("22222222-2222-2222-2222-222222222222"), 1)
	if bytes.Equal(badManifest, files["manifest.json"]) {
		t.Fatal("test setup: grouping id not found in manifest")
	}
	digest := sha256.Sum256(badManifest)
	if ed25519.Verify(signer.PublicKey(), digest[:], sig) {
		t.Error("signature verified over a re-attributed manifest — metadata is outside the envelope")
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
	// An unsigned build (nil signer) omits the signatures/ files entirely.
	for _, name := range []string{"signatures/bundle.sig", "signatures/chain.json"} {
		if _, ok := files[name]; ok {
			t.Errorf("unsigned bundle carries %s", name)
		}
	}
}
