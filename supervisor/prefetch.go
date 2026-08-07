package supervisor

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/sd-strax/reckon/internal/branding"
)

// PrefetchRuntimes downloads every distribution the supervised stack needs into
// runtimeDir — the pg/, temporal/, and keycloak/ subdirs runtime.serve expects
// when data.runtime_dir points there — without leaving any state behind
// (05 §12.4). It is the build-time half of the binaries/data split: the engine
// container image RUNs it so the published image boots with no first-run
// downloads (and works air-gapped); the same command prepares an offline
// bundle for host installs.
//
// Pg and Temporal are exercised via a throwaway boot (start + stop against a
// temp data dir on ephemeral ports) because their libraries download inside
// Start; Keycloak's JRE + server are fetched directly. All three skip work
// already present, so re-running is cheap and idempotent — and the throwaway
// boot doubles as proof the baked distributions actually run on this platform.
func PrefetchRuntimes(ctx context.Context, runtimeDir string, out io.Writer) error {
	tmp, err := os.MkdirTemp("", branding.CLI+"-prefetch-*")
	if err != nil {
		return fmt.Errorf("prefetch scratch dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	_, _ = fmt.Fprintf(out, "prefetching Postgres distribution → %s\n", filepath.Join(runtimeDir, "pg"))
	pgPort, err := pickFreePort()
	if err != nil {
		return err
	}
	pg := NewPostgres(PostgresConfig{
		DataDir:    filepath.Join(tmp, "pg"),
		RuntimeDir: filepath.Join(runtimeDir, "pg"),
		Port:       pgPort,
		Password:   "prefetch", // throwaway: the cluster lives in tmp and is deleted
	})
	if err := pg.Start(ctx); err != nil {
		return fmt.Errorf("prefetch postgres: %w", err)
	}
	if err := pg.Stop(ctx); err != nil {
		return fmt.Errorf("prefetch postgres stop: %w", err)
	}

	_, _ = fmt.Fprintf(out, "prefetching Temporal CLI → %s\n", filepath.Join(runtimeDir, "temporal"))
	tempPort, err := pickFreePort()
	if err != nil {
		return err
	}
	temp := NewTemporal(TemporalConfig{
		DataDir:      filepath.Join(tmp, "temporal"),
		BinDir:       filepath.Join(runtimeDir, "temporal"),
		FrontendPort: int(tempPort),
		EnableUI:     false,
	})
	if err := temp.Start(ctx); err != nil {
		return fmt.Errorf("prefetch temporal: %w", err)
	}
	if err := temp.Stop(ctx); err != nil {
		return fmt.Errorf("prefetch temporal stop: %w", err)
	}

	_, _ = fmt.Fprintf(out, "prefetching JRE + Keycloak → %s\n", filepath.Join(runtimeDir, "keycloak"))
	kc := NewKeycloak(KeycloakConfig{
		DataDir:    filepath.Join(tmp, "kc"),
		RuntimeDir: filepath.Join(runtimeDir, "keycloak"),
	})
	if err := kc.ensureBinaries(ctx); err != nil {
		return fmt.Errorf("prefetch keycloak: %w", err)
	}

	_, _ = fmt.Fprintf(out, "runtimes prefetched under %s\n", runtimeDir)
	return nil
}

// pickFreePort asks the kernel for an unused TCP port for the throwaway boots,
// so prefetch never collides with a live stack on the same host.
func pickFreePort() (uint32, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("pick free port: %w", err)
	}
	defer func() { _ = l.Close() }()
	return uint32(l.Addr().(*net.TCPAddr).Port), nil //nolint:gosec // ports fit uint32
}
