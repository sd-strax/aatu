package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/sd-strax/reckon/supervisor"
)

// runPrefetchRuntimes downloads the supervised stack's distributions
// (Postgres, Temporal CLI, JRE + Keycloak) into a runtime dir — the build-time
// half of the binaries/data split (05 §12.4). The engine container image runs
// it during `docker build` so the published image boots without first-run
// downloads; the same command prepares an offline bundle for air-gapped host
// installs. Point data.runtime_dir (or $RECKON_RUNTIME_DIR) at the dir to use
// it.
func runPrefetchRuntimes(args []string) error {
	fs := flag.NewFlagSet("prefetch-runtimes", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory to download the distributions into (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("--dir is required")
	}
	return supervisor.PrefetchRuntimes(context.Background(), *dir, os.Stdout)
}
