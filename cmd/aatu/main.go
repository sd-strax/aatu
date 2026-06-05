package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sd-strax/aatu/config"
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
	fmt.Fprintln(os.Stderr, "  status     report supervisor health (queries a running aatu instance)")
}

// runStart brings up the bundled-deps supervisor and blocks until the
// process receives SIGINT or SIGTERM. Stop is best-effort with a 30s
// deadline.
func runStart() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pg := supervisor.NewPostgres(supervisor.PostgresConfig{
		DataDir: filepath.Join(cfg.Data.Dir, "pg"),
		Port:    cfg.Postgres.Port,
		// Temporal manages its own SQLite store (see D15) so there's no
		// aatu_temporal database here today.
		Databases: []string{"aatu_main", "aatu_knowledge"},
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

	backend := supervisor.NewBackend(supervisor.BackendConfig{
		HTTPPort:         cfg.Backend.HTTPPort,
		PgDSN:            pg.DSN("aatu_main"),
		TemporalHostPort: fmt.Sprintf("localhost:%d", cfg.Temporal.FrontendPort),
		KeycloakIssuer: fmt.Sprintf("http://localhost:%d/realms/%s",
			cfg.Keycloak.HTTPPort, cfg.Keycloak.Realm),
	}, sup)
	sup.Register(backend, supervisor.RestartOnExit)

	if err := sup.Start(ctx); err != nil {
		return fmt.Errorf("supervisor start: %w", err)
	}
	log.Printf("aatu: bundled stack ready. /status on http://localhost:%d/status. Press Ctrl-C to stop.",
		cfg.Backend.HTTPPort)

	<-ctx.Done()
	log.Println("aatu: shutdown signal received")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer stopCancel()
	if err := sup.Stop(stopCtx); err != nil {
		return fmt.Errorf("supervisor stop: %w", err)
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

	var status supervisor.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return fmt.Errorf("parse /status response: %w", err)
	}

	fmt.Printf("aatu: %s\n", status.Overall)
	// Deterministic order so output is grep-friendly.
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

// orderedComponentNames returns supervisor component names in registration
// order. We use the well-known names rather than sorting alphabetically so
// the output reads top-down dependency order.
func orderedComponentNames(m map[string]supervisor.ComponentStatus) []string {
	preferred := []string{"postgres", "temporal", "keycloak", "backend"}
	seen := map[string]bool{}
	out := []string{}
	for _, n := range preferred {
		if _, ok := m[n]; ok {
			out = append(out, n)
			seen[n] = true
		}
	}
	// Append any unexpected components alphabetically so we don't drop them.
	extra := []string{}
	for n := range m {
		if !seen[n] {
			extra = append(extra, n)
		}
	}
	// stable order for extras: append in iteration order is non-deterministic;
	// we accept that for unexpected names.
	out = append(out, extra...)
	return out
}
