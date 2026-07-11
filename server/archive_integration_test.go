package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/archive"
	"github.com/sd-strax/reckon/module"
	"github.com/sd-strax/reckon/temporal"
)

// untarArchive reads a tar.gz into a name→bytes map (local copy — the archive
// package's helper is unexported to its own tests).
func untarArchive(t *testing.T, gzBytes []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		t.Fatalf("gzip: %v", err)
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
			t.Fatalf("tar: %v", err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = b
	}
	return out
}

// TestArchiveBundle_EndToEnd drives a real investigation to CONCLUDED with a
// hypothesis (carrying a transcript) and a succeeded action, then runs the
// ArchiveBundle activity against the embedded-Pg handler and asserts the signed
// bundle lands on disk, verifies, and carries the investigation's content.
func TestArchiveBundle_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	ctx := context.Background()
	invID := activeInvestigation(t)

	env := func(kind string) aggregate.Envelope {
		e := aggregate.Envelope{
			AggregateID: invID, TenantID: module.SingleTenantUUID, CorrelationID: uuid.New(),
			Actor: aggregate.Actor{PrincipalID: "analyst-1", Kind: kind}, OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		}
		if kind == aggregate.ActorAIDelegated {
			e.Actor.Delegate = &aggregate.AIDelegate{Vendor: "claude"}
		}
		return e
	}

	// A hypothesis with a transcript (exercises the STIX bundle + side stores).
	if _, err := testHandler.Handle(ctx, env(aggregate.ActorAIDelegated), aggregate.RecordInterpretation{
		InterpretationID:   uuid.New(),
		InterpretationType: aggregate.InterpretationHypothesis,
		Rationale:          "beaconing consistent with C2",
		Hypothesis:         &aggregate.HypothesisNode{ID: uuid.New(), Statement: "C2 via DNS tunneling", Labels: []string{"T1071.004"}},
		Transcript:         &aggregate.TranscriptContent{TranscriptID: uuid.New(), TurnID: "t1", Body: []byte("assistant: proposing H1")},
	}); err != nil {
		t.Fatalf("record hypothesis: %v", err)
	}

	// A succeeded action (exercises the action summary + more events).
	succeededAction(t, invID)

	// Conclude.
	if _, err := testHandler.Handle(ctx, env(""), aggregate.ConcludeInvestigation{
		ReportRef: "report--1", Summary: "Confirmed C2; host isolated.",
	}); err != nil {
		t.Fatalf("conclude: %v", err)
	}

	// Run the archive activity directly (the workflow just wraps it).
	signer, err := archive.GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	namespace := uuid.NewString()
	acts := temporal.NewArchiveActivities(testHandler, signer, t.TempDir())
	out, err := acts.ArchiveBundle(ctx, temporal.ArchiveBundleInput{
		GroupingID:        invID.String(),
		TenantID:          module.SingleTenantUUID.String(),
		TenantNamespace:   namespace,
		IncludeSideStores: true,
	})
	if err != nil {
		t.Fatalf("ArchiveBundle: %v", err)
	}
	if !strings.Contains(out.Path, namespace) || out.SizeBytes == 0 {
		t.Errorf("output = %+v; want a namespaced non-empty bundle", out)
	}

	// The bundle is on disk, exactly where the activity said.
	raw, err := os.ReadFile(out.Path)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	files := untarArchive(t, raw)

	// The report names the hypothesis and the action.
	report := string(files["investigation.report.md"])
	if !strings.Contains(report, "C2 via DNS tunneling") || !strings.Contains(report, "host.isolate") {
		t.Errorf("report missing expected content:\n%s", report)
	}

	// The STIX bundle carries the reasoning node.
	var stix struct {
		Objects []json.RawMessage `json:"objects"`
	}
	_ = json.Unmarshal(files["stix-bundle.json"], &stix)
	if len(stix.Objects) == 0 {
		t.Error("stix-bundle.json has no objects")
	}

	// The transcript landed in the side stores.
	foundTranscript := false
	for name := range files {
		if strings.HasPrefix(name, "side-stores/transcripts/") {
			foundTranscript = true
		}
	}
	if !foundTranscript {
		t.Error("no transcript in the bundle side stores")
	}

	// The detached signature verifies over the manifest bytes as shipped (the
	// signed envelope covers the metadata AND, via ContentHash, every file).
	var m archive.Manifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if m.ContentHash != out.ContentHash {
		t.Fatalf("manifest hash %s != activity hash %s", m.ContentHash, out.ContentHash)
	}
	sig, _ := hex.DecodeString(string(files["signatures/bundle.sig"]))
	digest := sha256.Sum256(files["manifest.json"])
	if !ed25519.Verify(signer.PublicKey(), digest[:], sig) {
		t.Error("bundle signature does not verify")
	}
}

// TestArchiveBundle_RejectsUnconcluded: an investigation that has not concluded
// is not exportable — a bundle is a finalized artifact.
func TestArchiveBundle_RejectsUnconcluded(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	invID := activeInvestigation(t) // ACTIVE, not concluded

	signer, _ := archive.GenerateEd25519Signer()
	acts := temporal.NewArchiveActivities(testHandler, signer, t.TempDir())
	_, err := acts.ArchiveBundle(context.Background(), temporal.ArchiveBundleInput{
		GroupingID:      invID.String(),
		TenantID:        module.SingleTenantUUID.String(),
		TenantNamespace: uuid.NewString(),
	})
	if err == nil || !strings.Contains(err.Error(), "CONCLUDED") {
		t.Fatalf("want a CONCLUDED-only rejection; got %v", err)
	}
}
