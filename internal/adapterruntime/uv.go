// Package adapterruntime provisions the ambient runtime an out-of-process
// adapter needs (design/11 §3 `requires`), so the operator installs nothing.
// It is the adapter analog of the supervisor's embedded-binary management: reckon
// downloads and pins the toolchain (here, uv) and builds the isolated
// environment, exactly as the supervisor downloads Postgres/Temporal/Keycloak.
//
// The friction this removes is real: wrapping a Python MCP server (okta-mcp-server)
// otherwise forces a user through "install the right Python, install uv, fetch the
// package, dodge the version that crashes" — none of which is the vendor's
// requirement, only the wrapper's. reckon owns that chain instead.
package adapterruntime

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// uvVersion is the pinned uv release (a single static Rust binary, no deps). Pin
// for reproducibility and air-gapped installs; bump deliberately.
const uvVersion = "0.12.1"

// uvTarget maps the Go platform to uv's release target triple.
func uvTarget() (string, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		return "aarch64-apple-darwin", nil
	case "darwin/amd64":
		return "x86_64-apple-darwin", nil
	case "linux/amd64":
		return "x86_64-unknown-linux-gnu", nil
	case "linux/arm64":
		return "aarch64-unknown-linux-gnu", nil
	default:
		return "", fmt.Errorf("no managed uv for %s/%s — install uv and set the adapter's server_command", runtime.GOOS, runtime.GOARCH)
	}
}

// EnsureUv downloads and caches the pinned uv under <dataDir>/tools/uv and
// returns the path to the uv binary. Idempotent: an existing binary (or an
// operator-placed one, the air-gap path) short-circuits the download.
func EnsureUv(ctx context.Context, dataDir string, out io.Writer) (string, error) {
	destDir := filepath.Join(dataDir, "tools", "uv")
	uvBin := filepath.Join(destDir, "uv")
	if _, err := os.Stat(uvBin); err == nil {
		return uvBin, nil
	}
	target, err := uvTarget()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://github.com/astral-sh/uv/releases/download/%s/uv-%s.tar.gz", uvVersion, target)
	_, _ = fmt.Fprintf(out, "downloading uv %s (%s)\n", uvVersion, target)
	if err := downloadTarGz(ctx, url, destDir, 1); err != nil {
		return "", err
	}
	if _, err := os.Stat(uvBin); err != nil {
		return "", fmt.Errorf("uv binary not found after extracting %s", url)
	}
	if err := os.Chmod(uvBin, 0o755); err != nil {
		return "", fmt.Errorf("chmod uv: %w", err)
	}
	return uvBin, nil
}

// symlinkStaysInside reports whether a relative symlink at linkPath pointing to
// linkname resolves within root — the containment guard for extracted symlinks.
func symlinkStaysInside(linkPath, linkname, root string) bool {
	resolved := filepath.Clean(filepath.Join(filepath.Dir(linkPath), linkname))
	rootClean := filepath.Clean(root)
	return resolved == rootClean || strings.HasPrefix(resolved, rootClean+string(filepath.Separator))
}

// downloadTarGz fetches a .tar.gz and extracts it into destDir, stripping the
// leading path components. Ported from the supervisor's downloader with the same
// traversal guards; sources here are trusted (pinned GitHub release URLs).
func downloadTarGz(ctx context.Context, url, destDir string, stripComponents int) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", destDir, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
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
		if relPath == "" || strings.Contains(relPath, "..") {
			continue
		}
		target := filepath.Join(destDir, relPath)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeSymlink:
			// The Node tarball ships npm/npx/corepack as relative symlinks into
			// lib/node_modules; recreate them. Refuse an absolute or escaping
			// linkname (defense in depth; sources are trusted pinned releases).
			if filepath.IsAbs(hdr.Linkname) || strings.Contains(hdr.Linkname, "..") && !symlinkStaysInside(target, hdr.Linkname, destDir) {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target) // replace any stale link
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("symlink %s -> %s: %w", target, hdr.Linkname, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return fmt.Errorf("open %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil { //nolint:gosec // trusted pinned release
				_ = f.Close()
				return fmt.Errorf("write %s: %w", target, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("close %s: %w", target, err)
			}
		}
	}
	return nil
}
