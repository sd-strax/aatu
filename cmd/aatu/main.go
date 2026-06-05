package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"github.com/sd-strax/aatu/aggregate"
	"github.com/sd-strax/aatu/config"
	"github.com/sd-strax/aatu/knowledge"
	"github.com/sd-strax/aatu/server"
	"github.com/sd-strax/aatu/supervisor"
)

// version is the OSS binary's version string. A build flag will stamp the
// git SHA once a release process exists; today it's a static label.
const version = "aatu OSS (dev)"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "start":
		if err := runStart(); err != nil {
			log.Fatalf("aatu start: %v", err)
		}
	case "stop":
		if err := runStop(); err != nil {
			log.Fatalf("aatu stop: %v", err)
		}
	case "status":
		if err := runStatus(); err != nil {
			log.Fatalf("aatu status: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: aatu <command>")
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintln(os.Stderr, "  version    print the aatu version")
	fmt.Fprintln(os.Stderr, "  start      bring up the bundled stack (Pg + Temporal + Keycloak + backend)")
	fmt.Fprintln(os.Stderr, "  stop       signal a running aatu supervisor to shut down")
	fmt.Fprintln(os.Stderr, "  status     report supervisor health (queries a running aatu instance)")
}

func pidFilePath(cfg config.Config) string {
	return filepath.Join(cfg.Data.Dir, "supervisor.pid")
}

// runStart builds the supervisor with all four components and calls Run,
// which blocks until shutdown (signal, fatal-exit, or restart-budget
// exhaustion). PID file is written on entry, removed on exit.
func runStart() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if err := writePIDFile(pidFilePath(cfg)); err != nil {
		return err
	}
	defer os.Remove(pidFilePath(cfg))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pg := supervisor.NewPostgres(supervisor.PostgresConfig{
		DataDir: filepath.Join(cfg.Data.Dir, "pg"),
		Port:    cfg.Postgres.Port,
		// Temporal manages its own SQLite store (see D15) so there's no
		// aatu_temporal database here today.
		Databases: []supervisor.DatabaseSpec{
			{Name: "aatu_main", Migrations: aggregate.Migrations()},
			{Name: "aatu_knowledge", Migrations: knowledge.Migrations()},
		},
	})
	temp := supervisor.NewTemporal(supervisor.TemporalConfig{
		DataDir:      filepath.Join(cfg.Data.Dir, "temporal"),
		FrontendPort: cfg.Temporal.FrontendPort,
		EnableUI:     cfg.Temporal.UIEnabled,
		UIPort:       cfg.Temporal.UIPort,
		Namespace:    cfg.Temporal.Namespace,
	})
	kc := supervisor.NewKeycloak(supervisor.KeycloakConfig{
		DataDir:        filepath.Join(cfg.Data.Dir, "keycloak"),
		HTTPPort:       cfg.Keycloak.HTTPPort,
		ManagementPort: cfg.Keycloak.ManagementPort,
		RealmName:      cfg.Keycloak.Realm,
	})

	sup := supervisor.New()
	sup.Register(pg, supervisor.FatalOnExit)
	sup.Register(temp, supervisor.RestartOnExit)
	sup.Register(kc, supervisor.RestartOnExit)

	// Open the aggregate's DB lazily — sql.Open doesn't actually connect
	// until first query, so it's safe to construct before Pg starts. The
	// Backend's probe verifies reachability before the HTTP server accepts
	// traffic.
	aggDB, err := sql.Open("postgres", pg.DSN("aatu_main"))
	if err != nil {
		return fmt.Errorf("open aggregate db: %w", err)
	}
	defer aggDB.Close()
	handler := aggregate.NewHandler(aggregate.NewStore(aggDB),
		aggregate.InvestigationCurrentProjector{},
	)

	backend := server.NewBackend(server.BackendConfig{
		HTTPPort:         cfg.Backend.HTTPPort,
		PgDSN:            pg.DSN("aatu_main"),
		TemporalHostPort: fmt.Sprintf("localhost:%d", cfg.Temporal.FrontendPort),
		KeycloakIssuer: fmt.Sprintf("http://localhost:%d/realms/%s",
			cfg.Keycloak.HTTPPort, cfg.Keycloak.Realm),
		Handler: handler,
	}, sup)
	sup.Register(backend, supervisor.RestartOnExit)

	log.Printf("aatu: pid %d; /status on http://localhost:%d/status; aatu stop to shut down",
		os.Getpid(), cfg.Backend.HTTPPort)

	if err := sup.Run(ctx); err != nil {
		return fmt.Errorf("supervisor: %w", err)
	}
	log.Println("aatu: stopped")
	return nil
}

// runStatus queries the running aatu instance's /status endpoint and prints
// a human-readable rollup. Exits non-zero if the instance is unreachable or
// any component reports degraded.
func runStatus() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	url := fmt.Sprintf("http://localhost:%d/status", cfg.Backend.HTTPPort)
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("aatu not reachable at %s — is the supervisor running?", url)
	}
	defer resp.Body.Close()

	var status server.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return fmt.Errorf("parse /status response: %w", err)
	}

	fmt.Printf("aatu: %s\n", status.Overall)
	for _, name := range orderedComponentNames(status.Components) {
		c := status.Components[name]
		mark := "✓"
		if !c.Ready {
			mark = "✗"
		}
		fmt.Printf("  %s %-10s %s\n", mark, name, c.Message)
	}
	if status.Overall != "ok" {
		os.Exit(1)
	}
	return nil
}

// runStop reads the PID file, sends SIGTERM to the running supervisor, and
// waits up to 45s for the file to disappear (which the supervisor removes on
// clean exit).
func runStop() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	path := pidFilePath(cfg)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no PID file at %s — is the supervisor running?", path)
		}
		return fmt.Errorf("read PID file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("malformed PID file at %s: %w", path, err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("send SIGTERM to %d: %w", pid, err)
	}
	fmt.Printf("aatu: sent SIGTERM to supervisor pid %d; waiting for shutdown\n", pid)

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			fmt.Println("aatu: stopped")
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("supervisor did not stop within 45s; PID file still present at %s", path)
}

// orderedComponentNames returns supervisor component names in registration
// order. We use the well-known names rather than sorting alphabetically so
// the output reads top-down dependency order.
func orderedComponentNames(m map[string]server.ComponentStatus) []string {
	preferred := []string{"postgres", "temporal", "keycloak", "backend"}
	seen := map[string]bool{}
	out := []string{}
	for _, n := range preferred {
		if _, ok := m[n]; ok {
			out = append(out, n)
			seen[n] = true
		}
	}
	for n := range m {
		if !seen[n] {
			out = append(out, n)
		}
	}
	return out
}

// writePIDFile records this process's PID for `aatu stop` to find. If an
// existing PID file points at a process that's still alive, refuses to
// overwrite — protects against accidentally running two supervisors.
func writePIDFile(path string) error {
	if data, err := os.ReadFile(path); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && isProcessAlive(pid) {
			return fmt.Errorf("another supervisor (pid %d) is running; stop it first with `aatu stop`, or remove %s if you know it's stale",
				pid, path)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o644)
}

// isProcessAlive probes via Signal(0) — the canonical Unix way to test
// whether a PID is a live process.
func isProcessAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
