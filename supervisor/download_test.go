package supervisor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeTarGz builds an in-memory tar.gz for tests. Each entry is
// (path-in-tar, body-or-"" for directories).
func makeTarGz(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, e := range entries {
		path, body := e[0], e[1]
		typeflag := byte(tar.TypeReg)
		if body == "" {
			typeflag = tar.TypeDir
		}
		hdr := &tar.Header{
			Name:     path,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: typeflag,
			ModTime:  time.Now(),
		}
		if typeflag == tar.TypeDir {
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader %s: %v", path, err)
		}
		if body != "" {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatalf("tar Write %s: %v", path, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func TestDownloadAndExtractTarGz_StripComponentsAndIdempotent(t *testing.T) {
	tarball := makeTarGz(t, [][2]string{
		{"toplevel/", ""},
		{"toplevel/bin/", ""},
		{"toplevel/bin/marker", "hello"},
		{"toplevel/lib/data.txt", "world"},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarball)
	}))
	t.Cleanup(srv.Close)

	dest := t.TempDir()
	markerRel := filepath.Join("bin", "marker")
	if err := downloadAndExtractTarGz(context.Background(), srv.URL, dest, markerRel, 1); err != nil {
		t.Fatalf("extract: %v", err)
	}

	// Verify file content (stripComponents=1 should have removed "toplevel/")
	got, err := os.ReadFile(filepath.Join(dest, markerRel))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("marker content = %q; want %q", got, "hello")
	}

	got2, err := os.ReadFile(filepath.Join(dest, "lib", "data.txt"))
	if err != nil {
		t.Fatalf("read lib/data.txt: %v", err)
	}
	if string(got2) != "world" {
		t.Errorf("lib/data.txt = %q; want %q", got2, "world")
	}

	// Idempotent: second call should be a no-op even with an invalid URL
	// (because the marker file already exists).
	if err := downloadAndExtractTarGz(context.Background(), "http://invalid.invalid", dest, markerRel, 1); err != nil {
		t.Errorf("expected no-op when marker exists; got %v", err)
	}
}

func TestDownloadAndExtractTarGz_RejectsPathTraversal(t *testing.T) {
	tarball := makeTarGz(t, [][2]string{
		{"toplevel/", ""},
		{"toplevel/../escape", "bad"},
		{"toplevel/bin/marker", "hello"},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarball)
	}))
	t.Cleanup(srv.Close)

	dest := t.TempDir()
	if err := downloadAndExtractTarGz(context.Background(), srv.URL, dest, filepath.Join("bin", "marker"), 1); err != nil {
		t.Fatalf("extract: %v", err)
	}

	// The "..escape" entry should NOT have been created anywhere outside dest.
	parent := filepath.Dir(dest)
	if _, err := os.Stat(filepath.Join(parent, "escape")); err == nil {
		t.Errorf("path traversal succeeded: file extracted outside dest")
	}
}

func TestDownloadAndExtractTarGz_HTTPErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	dest := t.TempDir()
	err := downloadAndExtractTarGz(context.Background(), srv.URL, dest, "marker", 0)
	if err == nil {
		t.Fatalf("expected error for HTTP 500; got nil")
	}
}

func TestDownloadAndExtractTarGz_MissingMarkerAfterExtraction(t *testing.T) {
	// Tarball doesn't contain the expected marker → should error after extraction
	tarball := makeTarGz(t, [][2]string{
		{"toplevel/other.txt", "data"},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarball)
	}))
	t.Cleanup(srv.Close)

	dest := t.TempDir()
	err := downloadAndExtractTarGz(context.Background(), srv.URL, dest, "expected-marker", 1)
	if err == nil {
		t.Fatalf("expected error when marker file missing post-extract; got nil")
	}
}
