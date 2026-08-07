package adapterruntime

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// nodeVersion is the pinned Node.js release. Node ships as a self-contained
// per-platform tarball (its own bundled npm/npx), so — exactly like the managed
// uv — reckon downloads and pins it and the operator installs nothing. Pin to an
// LTS; bump deliberately.
const nodeVersion = "22.11.0"

// nodeModulesDir is where npm installs the adapter's package inside its install
// dir; the manifest exec points at ./node_modules/.bin/<entrypoint>.
const nodeModulesDir = "node_modules"

// nodeProvisionMarker records the exact (node, package@version) spec provisioned,
// so a re-run is a no-op unless the pin changed.
const nodeProvisionMarker = "node_modules/.reckon-provisioned"

// nodeTarget maps the Go platform to Node's release tarball naming
// (node-v<ver>-<os>-<arch>).
func nodeTarget() (string, error) {
	var arch string
	switch runtime.GOARCH {
	case "arm64":
		arch = "arm64"
	case "amd64":
		arch = "x64"
	default:
		return "", fmt.Errorf("no managed Node for arch %s — install Node and set the adapter's server_command", runtime.GOARCH)
	}
	switch runtime.GOOS {
	case "darwin", "linux":
		return fmt.Sprintf("node-v%s-%s-%s", nodeVersion, runtime.GOOS, arch), nil
	default:
		return "", fmt.Errorf("no managed Node for %s/%s — install Node and set the adapter's server_command", runtime.GOOS, runtime.GOARCH)
	}
}

// EnsureNode downloads and caches the pinned Node under <dataDir>/tools/node and
// returns the path to its bin directory (holding node + npm + npx). Idempotent:
// an existing node binary (or an operator-placed one, the air-gap path)
// short-circuits the download.
func EnsureNode(ctx context.Context, dataDir string, out io.Writer) (string, error) {
	destDir := filepath.Join(dataDir, "tools", "node")
	binDir := filepath.Join(destDir, "bin")
	nodeBin := filepath.Join(binDir, "node")
	if _, err := os.Stat(nodeBin); err == nil {
		return binDir, nil
	}
	target, err := nodeTarget()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://nodejs.org/dist/v%s/%s.tar.gz", nodeVersion, target)
	_, _ = fmt.Fprintf(out, "downloading Node %s (%s)\n", nodeVersion, target)
	if err := downloadTarGz(ctx, url, destDir, 1); err != nil {
		return "", err
	}
	if _, err := os.Stat(nodeBin); err != nil {
		return "", fmt.Errorf("node binary not found after extracting %s", url)
	}
	if err := os.Chmod(nodeBin, 0o755); err != nil {
		return "", fmt.Errorf("chmod node: %w", err)
	}
	return binDir, nil
}

// ProvisionNode installs the pinned npm package into <adapterDir>/node_modules
// using the managed Node's npm (design/11 §3). Idempotent: an unchanged
// (package==version) spec short-circuits. nodeBinDir is the managed Node's bin
// directory from EnsureNode. Progress streams to out.
func ProvisionNode(ctx context.Context, nodeBinDir, adapterDir, pkg, pkgVersion string, out io.Writer) error {
	if pkg == "" {
		return fmt.Errorf("node runtime requires a package")
	}
	spec := pkg
	if pkgVersion != "" {
		spec += "@" + pkgVersion
	}
	pin := "node " + spec

	markerPath := filepath.Join(adapterDir, nodeProvisionMarker)
	if data, err := os.ReadFile(markerPath); err == nil && strings.TrimSpace(string(data)) == pin {
		_, _ = fmt.Fprintf(out, "already provisioned: %s\n", pin)
		return nil
	}

	_, _ = fmt.Fprintf(out, "installing %s (node %s)\n", spec, nodeVersion)
	// `npm install <spec> --prefix <dir>` installs into <dir>/node_modules and
	// links the package's bins into <dir>/node_modules/.bin. --no-fund/--no-audit
	// keep the setup output clean and offline-friendly.
	if err := runNpm(ctx, nodeBinDir, adapterDir, out, "install", spec, "--prefix", adapterDir, "--no-fund", "--no-audit"); err != nil {
		return fmt.Errorf("npm install %s: %w", spec, err)
	}
	if err := os.WriteFile(markerPath, []byte(pin+"\n"), 0o644); err != nil {
		return fmt.Errorf("write provision marker: %w", err)
	}
	return nil
}

// NodeEntrypointPath returns the path to a provisioned npm package's bin script,
// relative to the adapter install dir (matching the adapter's spawn cwd).
func NodeEntrypointPath(entrypoint string) string {
	return filepath.Join(".", nodeModulesDir, ".bin", entrypoint)
}

// NodeProvisioned reports whether an adapter dir has the package installed for
// the spec.
func NodeProvisioned(adapterDir, pkg, pkgVersion string) bool {
	spec := pkg
	if pkgVersion != "" {
		spec += "@" + pkgVersion
	}
	data, err := os.ReadFile(filepath.Join(adapterDir, nodeProvisionMarker))
	return err == nil && strings.TrimSpace(string(data)) == "node "+spec
}

// runNpm runs the managed Node's npm with node on PATH (npm is a node script).
func runNpm(ctx context.Context, nodeBinDir, dir string, out io.Writer, args ...string) error {
	npm := filepath.Join(nodeBinDir, "npm")
	cmd := exec.CommandContext(ctx, npm, args...) //nolint:gosec // npm is reckon's managed binary; args are constructed here
	cmd.Dir = dir
	cmd.Stdout = out
	cmd.Stderr = out
	// npm resolves `node` from PATH; prepend the managed bin dir so it uses the
	// pinned interpreter, not whatever (if anything) the operator has.
	cmd.Env = append(os.Environ(), "PATH="+nodeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return cmd.Run()
}
