package supervisor

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// downloadAndExtractTarGz fetches a .tar.gz from url and extracts it into
// destDir. If markerFile (relative to destDir) already exists, the call is a
// no-op — this is the "pre-extracted bundle wins" semantic that makes
// air-gapped installs work without any code changes.
//
// stripComponents removes that many leading path components from each entry
// (analogous to tar's --strip-components). A Temurin or Keycloak tarball
// usually has a single top-level directory; setting stripComponents=1 places
// the contents directly under destDir.
func downloadAndExtractTarGz(ctx context.Context, url, destDir, markerFile string, stripComponents int) error {
	if _, err := os.Stat(filepath.Join(destDir, markerFile)); err == nil {
		return nil
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", destDir, err)
	}

	log.Printf("supervisor: downloading %s", url)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}

		parts := strings.Split(hdr.Name, "/")
		if len(parts) <= stripComponents {
			continue
		}
		relPath := strings.Join(parts[stripComponents:], "/")
		if relPath == "" {
			continue
		}
		// Reject paths that try to escape destDir (defense in depth against
		// malicious tarballs even though our sources are trusted).
		if strings.Contains(relPath, "..") {
			continue
		}

		target := filepath.Join(destDir, relPath)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return fmt.Errorf("open %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return fmt.Errorf("write %s: %w", target, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("close %s: %w", target, err)
			}
		case tar.TypeSymlink:
			// Validate the link target, not just the entry name: an absolute
			// or dot-dot Linkname would point outside destDir, and later
			// entries writing through it would escape the extraction root.
			if filepath.IsAbs(hdr.Linkname) {
				return fmt.Errorf("symlink %s has absolute target %s: refusing", relPath, hdr.Linkname)
			}
			// This Join IS the traversal guard: it resolves the link target so
			// the Rel check below can refuse anything outside destDir.
			resolved := filepath.Join(filepath.Dir(target), hdr.Linkname) //nolint:gosec // G305: resolved is validated against destDir on the next line, never used raw
			rel, err := filepath.Rel(destDir, resolved)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("symlink %s target %s escapes %s: refusing", relPath, hdr.Linkname, destDir)
			}
			_ = os.Remove(target)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("symlink %s -> %s: %w", target, hdr.Linkname, err)
			}
		}
	}

	if _, err := os.Stat(filepath.Join(destDir, markerFile)); err != nil {
		return fmt.Errorf("expected marker %s not found after extraction", markerFile)
	}

	return nil
}
