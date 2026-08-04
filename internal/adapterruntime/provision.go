package adapterruntime

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// VenvDir is the isolated environment reckon builds inside an adapter's install
// directory. The manifest's exec points into it (e.g. ./.venv/bin/<entrypoint>),
// so the adapter runs deterministically and offline after provisioning.
const VenvDir = ".venv"

// provisionMarker records the exact spec the venv was provisioned for, so a
// re-run is a no-op unless the pin changed (a version bump re-provisions).
const provisionMarker = ".venv/.reckon-provisioned"

// ProvisionPython builds an isolated venv under <adapterDir>/.venv with the
// pinned Python and installs the pinned package (design/11 §3). It is
// idempotent: an unchanged (python, package==version) spec short-circuits.
// uvBin is the managed uv from EnsureUv. Progress streams to out.
func ProvisionPython(ctx context.Context, uvBin, adapterDir, python, pkg, pkgVersion string, out io.Writer) error {
	if python == "" || pkg == "" {
		return fmt.Errorf("python runtime requires both a python version and a package")
	}
	spec := pkg
	if pkgVersion != "" {
		spec += "==" + pkgVersion
	}
	pin := python + " " + spec

	markerPath := filepath.Join(adapterDir, provisionMarker)
	if data, err := os.ReadFile(markerPath); err == nil && strings.TrimSpace(string(data)) == pin {
		_, _ = fmt.Fprintf(out, "already provisioned: %s\n", pin)
		return nil
	}

	venv := filepath.Join(adapterDir, VenvDir)
	_, _ = fmt.Fprintf(out, "creating venv (python %s)\n", python)
	if err := runUv(ctx, uvBin, adapterDir, out, "venv", "--python", python, venv); err != nil {
		return fmt.Errorf("uv venv: %w", err)
	}
	_, _ = fmt.Fprintf(out, "installing %s\n", spec)
	py := filepath.Join(venv, "bin", "python")
	if err := runUv(ctx, uvBin, adapterDir, out, "pip", "install", "--python", py, spec); err != nil {
		return fmt.Errorf("uv pip install %s: %w", spec, err)
	}
	if err := os.WriteFile(markerPath, []byte(pin+"\n"), 0o644); err != nil {
		return fmt.Errorf("write provision marker: %w", err)
	}
	return nil
}

// EntrypointPath returns the path to a provisioned venv console script, relative
// to the adapter install dir (so it matches the adapter's spawn cwd).
func EntrypointPath(entrypoint string) string {
	return filepath.Join(".", VenvDir, "bin", entrypoint)
}

// Provisioned reports whether an adapter dir has a completed venv for the spec.
func Provisioned(adapterDir, python, pkg, pkgVersion string) bool {
	spec := pkg
	if pkgVersion != "" {
		spec += "==" + pkgVersion
	}
	data, err := os.ReadFile(filepath.Join(adapterDir, provisionMarker))
	return err == nil && strings.TrimSpace(string(data)) == python+" "+spec
}

func runUv(ctx context.Context, uvBin, dir string, out io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, uvBin, args...) //nolint:gosec // uvBin is reckon's managed binary; args are constructed here
	cmd.Dir = dir
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.Env = os.Environ() // uv needs HOME (cache) + network; this is the setup tool, not the sandboxed adapter
	return cmd.Run()
}
