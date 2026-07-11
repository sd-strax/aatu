package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/module"
	"github.com/sd-strax/reckon/runtime"
	"github.com/sd-strax/reckon/server"
)

// version is the OSS binary's version string. A build flag will stamp the
// git SHA once a release process exists; today it's a static label.
var version = fmt.Sprintf("%s OSS (dev)", branding.CLI)

// ossModuleBuilder is the OSS registry builder: always-disabled paid stubs.
// It is the OSS half of the one seam where OSS and paid binaries diverge; the
// paid binary injects a builder that activates real modules. Everything the
// builder feeds (boot, supervisor, server) lives in the shared runtime package.
func ossModuleBuilder(runtime.Config) module.Registry {
	return module.Registry{
		Tenancy:    module.DisabledTenancy{},
		Governance: module.DisabledGovernance{},
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "init":
		if err := runInit(); err != nil {
			log.Fatalf("%s init: %v", branding.CLI, err)
		}
	case "start":
		if err := runtime.Run(ossModuleBuilder); err != nil {
			log.Fatalf("%s start: %v", branding.CLI, err)
		}
	case "check":
		if err := runtime.Preflight(ossModuleBuilder); err != nil {
			log.Fatalf("%s check: %v", branding.CLI, err)
		}
	case "stop":
		if err := runStop(); err != nil {
			log.Fatalf("%s stop: %v", branding.CLI, err)
		}
	case "status":
		if err := runStatus(); err != nil {
			log.Fatalf("%s status: %v", branding.CLI, err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <command>\n", branding.CLI)
	fmt.Fprintln(os.Stderr, "commands:")
	fmt.Fprintf(os.Stderr, "  version    print the %s version\n", branding.CLI)
	fmt.Fprintln(os.Stderr, "  init       first-run setup: write a default config with a fresh identity namespace")
	fmt.Fprintln(os.Stderr, "  start      bring up the bundled stack (Pg + Temporal + Keycloak + backend)")
	fmt.Fprintln(os.Stderr, "  check      validate config + module activation without starting services")
	fmt.Fprintf(os.Stderr, "  stop       signal a running %s supervisor to shut down\n", branding.CLI)
	fmt.Fprintf(os.Stderr, "  status     report supervisor health (queries a running %s instance)\n", branding.CLI)
}

// runInit performs first-run setup: writes a default config with a freshly
// minted per-install identity namespace (runtime.Init), then prints the config
// location + the next steps. Idempotent — re-running against an existing config
// reports it rather than overwriting.
func runInit() error {
	res, err := runtime.Init()
	if err != nil {
		return err
	}
	if res.AlreadyExisted {
		fmt.Printf("%s is already initialized.\n", branding.CLI)
		fmt.Printf("  config:    %s\n", res.ConfigPath)
		fmt.Printf("  namespace: %s\n", res.TenantNamespace)
		fmt.Printf("\nEdit the config to change ports/paths, then run `%s start`.\n", branding.CLI)
		return nil
	}
	fmt.Printf("%s initialized.\n", branding.CLI)
	fmt.Printf("  config:    %s\n", res.ConfigPath)
	fmt.Printf("  data dir:  %s\n", res.DataDir)
	fmt.Printf("  namespace: %s  (this install's immutable identity namespace)\n", res.TenantNamespace)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. %s start                 — bring up the bundled stack (first run downloads Pg/Temporal/Keycloak)\n", branding.CLI)
	fmt.Printf("  2. sign in to the bundled realm (default user reckon-admin / reckon; change on first login)\n")
	fmt.Printf("  3. set capability.config_path in the config to a tenant capability YAML to investigate real or fixture data\n")
	return nil
}

// runStatus queries the running supervisor's /status endpoint and prints
// a human-readable rollup. Exits non-zero if the instance is unreachable
// or any component reports degraded.
func runStatus() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	url := fmt.Sprintf("http://localhost:%d/status", cfg.Backend.HTTPPort)
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("%s not reachable at %s — is the supervisor running?", branding.CLI, url)
	}
	var status server.StatusResponse
	decErr := json.NewDecoder(resp.Body).Decode(&status)
	_ = resp.Body.Close()
	if decErr != nil {
		return fmt.Errorf("parse /status response: %w", decErr)
	}

	fmt.Printf("%s: %s\n", branding.CLI, status.Overall)
	for _, name := range orderedComponentNames(status.Components) {
		c := status.Components[name]
		mark := "✓"
		if !c.Ready {
			mark = "✗"
		}
		fmt.Printf("  %s %-10s %s\n", mark, name, c.Message)
	}
	if status.Overall != "ok" {
		// Body already closed above so os.Exit doesn't skip cleanup.
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
	path := runtime.PIDFilePath(cfg)

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
	fmt.Printf("%s: sent SIGTERM to supervisor pid %d; waiting for shutdown\n", branding.CLI, pid)

	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			fmt.Printf("%s: stopped\n", branding.CLI)
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
