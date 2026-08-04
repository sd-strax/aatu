package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/internal/bundledadapters"
)

// runAdapterInstall places a bundled first-party adapter into the data dir so the
// operator never runs mkdir/cp/go-build. It writes the embedded manifest and
// copies the adapter executable (built alongside reckon by `make build`,
// resolved as a sibling of the running reckon binary) into
// <data>/adapters/<name>/. Idempotent: re-installing overwrites in place.
//
//	reckon adapter install okta
func runAdapterInstall(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: %s adapter install <name>  (available: %s)", branding.CLI, strings.Join(bundledadapters.Names(), ", "))
	}
	name := args[0]
	b, ok := bundledadapters.Get(name)
	if !ok {
		return fmt.Errorf("no bundled adapter %q (available: %s)", name, strings.Join(bundledadapters.Names(), ", "))
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	dir, err := installBundled(b, cfg)
	if err != nil {
		return err
	}
	fmt.Printf("✓ installed %s → %s\n", name, dir)
	fmt.Printf("next: %s adapter setup %s\n", branding.CLI, name)
	return nil
}

// installBundled writes a bundled adapter's manifest and copies its executable
// into <data>/adapters/<name>/, returning the install dir. Shared by the
// `install` command and by `setup`'s auto-install.
func installBundled(b bundledadapters.Bundled, cfg config.Config) (string, error) {
	dir := filepath.Join(cfg.Data.Dir, "adapters", b.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), b.Manifest, 0o644); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}
	src, err := siblingBinary(b.Binary)
	if err != nil {
		return "", err
	}
	if err := copyExecutable(src, filepath.Join(dir, b.Binary)); err != nil {
		return "", err
	}
	return dir, nil
}

// siblingBinary resolves an adapter executable built next to the running reckon
// binary (make build puts them together in bin/).
func siblingBinary(binary string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate reckon binary: %w", err)
	}
	src := filepath.Join(filepath.Dir(exe), binary)
	if _, err := os.Stat(src); err != nil {
		return "", fmt.Errorf("adapter binary %q not found next to %s — run `make build` first (%w)", binary, branding.CLI, err)
	}
	return src, nil
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // src is a reckon-built sibling binary path
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy adapter binary: %w", err)
	}
	return out.Close()
}
