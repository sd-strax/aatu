package main

import (
	"encoding/json"
	"errors"
	"flag"
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
	"github.com/sd-strax/reckon/internal/secrets"
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
		if err := runInit(os.Args[2:]); err != nil {
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
	case "investigate":
		arg := ""
		if len(os.Args) > 2 {
			arg = os.Args[2]
		}
		if arg == "--stdio" {
			// Sidecar mode: the workbench spawns this and speaks JSON-RPC over
			// stdio (implementation/agent-sidecar.md §4). No investigation id —
			// sessions name their investigation over the protocol.
			if err := runSidecar(); err != nil {
				log.Fatalf("%s investigate --stdio: %v", branding.CLI, err)
			}
			return
		}
		if err := runInvestigate(arg); err != nil {
			log.Fatalf("%s investigate: %v", branding.CLI, err)
		}
	case "dev-auth":
		if err := runDevAuth(os.Args[2:]); err != nil {
			log.Fatalf("%s dev-auth: %v", branding.CLI, err)
		}
	case "adapter":
		if err := runAdapter(os.Args[2:]); err != nil {
			log.Fatalf("%s adapter: %v", branding.CLI, err)
		}
	case "set-anthropic-key":
		if err := runSetAnthropicKey(); err != nil {
			log.Fatalf("%s set-anthropic-key: %v", branding.CLI, err)
		}
	case "unset-anthropic-key":
		if err := runUnsetAnthropicKey(); err != nil {
			log.Fatalf("%s unset-anthropic-key: %v", branding.CLI, err)
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
	fmt.Fprintln(os.Stderr, "  investigate <id>  interactive agent loop over an investigation (BYOK Anthropic key)")
	fmt.Fprintln(os.Stderr, "  investigate --stdio  agent-loop sidecar for the workbench (JSON-RPC over stdio; spawned, not typed)")
	fmt.Fprintln(os.Stderr, "  adapter install <name>  install a bundled first-party adapter (okta) into the data dir")
	fmt.Fprintln(os.Stderr, "  adapter setup <name>  provision an installed adapter's runtime (managed uv + venv) and run its one-time login")
	fmt.Fprintln(os.Stderr, "  adapter test <dir>  run the plugin conformance handshake against an adapter directory (11 §7)")
	fmt.Fprintln(os.Stderr, "  dev-auth   provision a local dev/CI login principal + enable the direct grant (dev/CI ONLY)")
	fmt.Fprintln(os.Stderr, "  set-anthropic-key    store your BYOK Anthropic key in the OS keychain (client-side)")
	fmt.Fprintln(os.Stderr, "  unset-anthropic-key  remove the stored Anthropic key from the keychain")
}

// runInit performs first-run setup (the deployer step): writes a default config
// with a freshly minted per-install identity namespace and establishes the
// install's secrets. No credential is ever auto-generated — each of the Keycloak
// master-admin and Postgres passwords enters by an explicit act: a --*-password
// flag (persisted to the store), a bare env override (RECKON_KC_PASSWORD /
// RECKON_PG_PASSWORD with no flag → injected at runtime, NOT persisted — the
// vault path), or, on a terminal, an interactive no-echo prompt (persisted).
// A no-source secret on a non-interactive run fails fast. Idempotent: re-running
// reports the existing config and never rotates or re-prompts a set secret.
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	kcAdminPassword := fs.String("kc-admin-password", "",
		"persist this master-admin password to the store (else inject "+secrets.EnvKeycloakAdmin+" at runtime, or be prompted)")
	pgPassword := fs.String("postgres-password", "",
		"persist this Postgres role password to the store (else inject "+secrets.EnvPostgres+" at runtime, or be prompted)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// A bare env override (no persist flag) means the secret is injected at
	// runtime and must NOT be written to disk — the operator/vault path.
	kcExternal := *kcAdminPassword == "" && os.Getenv(secrets.EnvKeycloakAdmin) != ""
	pgExternal := *pgPassword == "" && os.Getenv(secrets.EnvPostgres) != ""

	// On a terminal, a secret with no flag/env source is prompted (no echo)
	// rather than generated. Off a terminal we pass no prompter, so init fails
	// fast pointing at the flag/env — never conjuring a credential.
	var prompt func(name, label string) (string, error)
	if stdinIsTerminal() {
		prompt = func(_ /*name*/, label string) (string, error) { return promptNewPassword(label) }
	}

	res, err := runtime.Init(runtime.InitOptions{
		KeycloakAdminPassword: *kcAdminPassword,
		KeycloakAdminExternal: kcExternal,
		PostgresPassword:      *pgPassword,
		PostgresExternal:      pgExternal,
		PromptForSecret:       prompt,
	})
	if err != nil {
		return err
	}

	// Report each secret's source. Nothing is ever generated, so a password is
	// never echoed — the operator supplied or typed it and already has it. We
	// only name WHERE it now lives: env-injected (unpersisted) vs the store, and
	// distinguish "set this run" from an idempotent no-op on re-init.
	printKCAdmin := func() {
		switch {
		case res.KeycloakAdminExternal:
			fmt.Printf("  keycloak admin: injected via %s at runtime (not persisted)\n", secrets.EnvKeycloakAdmin)
		case res.KeycloakAdminSetFromInput:
			fmt.Printf("  keycloak admin: master-admin password set (in secrets/, read by `%s dev-auth`)\n", branding.CLI)
		default:
			fmt.Printf("  keycloak admin: master-admin password already provisioned (in secrets/)\n")
		}
	}
	printPostgres := func() {
		if res.PostgresExternal {
			fmt.Printf("  postgres:       injected via %s at runtime (not persisted)\n", secrets.EnvPostgres)
		} else {
			fmt.Printf("  postgres:       role password provisioned (in secrets/)\n")
		}
	}

	if res.AlreadyExisted {
		fmt.Printf("%s is already initialized.\n", branding.CLI)
		fmt.Printf("  config:    %s\n", res.ConfigPath)
		fmt.Printf("  namespace: %s\n", res.TenantNamespace)
		printKCAdmin()
		printPostgres()
		fmt.Printf("\nEdit the config to change ports/paths, then run `%s start`.\n", branding.CLI)
		return nil
	}
	fmt.Printf("%s initialized.\n", branding.CLI)
	fmt.Printf("  config:    %s\n", res.ConfigPath)
	fmt.Printf("  data dir:  %s\n", res.DataDir)
	fmt.Printf("  namespace: %s  (this install's immutable identity namespace)\n", res.TenantNamespace)
	fmt.Printf("  demo:      %s  (fixture scenario, wired live via %s)\n", res.SeededScenario, res.CapabilityConfig)
	printKCAdmin()
	printPostgres()
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. %s start                 — bring up the bundled stack (first run downloads Pg/Temporal/Keycloak)\n", branding.CLI)
	fmt.Printf("  2. %s dev-auth              — provision a local dev login (the shipped realm carries no credentials)\n", branding.CLI)
	fmt.Printf("  3. sign in with the principal dev-auth prints, then GET /api/capabilities — the seeded %s scenario's verbs are live\n",
		res.SeededScenario)
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
