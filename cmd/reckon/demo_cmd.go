package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sd-strax/reckon/agent"
	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/runtime"
)

// runDemo dispatches the `demo` subcommands — the bundled demo world's
// lifecycle. `seed` populates a virgin install (fixtures + capability config +
// knowledge pack) so an analyst can test-drive the full product; `reset` wipes
// everything back to a clean, real install. The two are gated so neither can
// touch a working instance by accident (config.Demo).
func runDemo(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: %s demo <seed|reset>", branding.CLI)
	}
	switch args[0] {
	case "seed":
		return runDemoSeed(args[1:])
	case "reset":
		return runDemoReset(args[1:])
	default:
		return fmt.Errorf("unknown demo subcommand %q (want: seed | reset)", args[0])
	}
}

// runDemoSeed populates a fresh install with the bundled demo world. It requires
// the stack to be RUNNING (it loads the demo knowledge into the live backend,
// where the virginity guard is enforced server-side), then materializes the
// fixtures + capability config on disk and flips demo.enabled. A restart
// activates the fixture-backed capabilities.
func runDemoSeed(args []string) error {
	fl := flag.NewFlagSet("demo seed", flag.ContinueOnError)
	user := fl.String("user", envOrDefault("RECKON_USER", branding.CLI+"-admin"), "backend login user (or RECKON_USER)")
	pass := fl.String("password", os.Getenv("RECKON_PASSWORD"), "backend login password (or RECKON_PASSWORD)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *pass == "" {
		*pass = branding.CLI // the dev-auth default, same as `knowledge import`
	}

	path, err := config.DefaultPath()
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Vector recall is the point of the demo — the knowledge rail's relevance
	// scores, similarity bands, and the "similar past case" recall are all
	// cosine-only; without an embedder they degrade to keyword fallback, which
	// reads as a half-finished product. And the seed embeds the prior cases at
	// write time, so an embedder must be live BEFORE seeding (a case stored with
	// no vector makes later similarity recall error, not degrade). A running
	// backend with embeddings configured necessarily has a live embedder
	// (buildKnowledge fails startup otherwise), so this file-level check is a
	// sound proxy for the backend's state under the demo's configure→start→seed
	// order. Refuse early, before touching the network.
	if cfg.Knowledge.Embeddings.BaseURL == "" {
		return fmt.Errorf("configure an embeddings backend before seeding the demo — vector recall powers the knowledge rail and similar-case retrieval.\n"+
			"  add a knowledge.embeddings block to your config (base_url + model + api_key), then `%s start`.\n"+
			"  see implementation/demo-script.md for the exact block", branding.CLI)
	}

	// The knowledge pack lands in the running backend's database, so the stack
	// must be up. (The fixtures + config are disk-only, but seeding knowledge is
	// the guarded, authoritative step — do it first so a non-virgin install is
	// refused before anything touches disk.)
	if !backendReachable(cfg) {
		return fmt.Errorf("the stack must be running for `%s demo seed` — it loads the demo knowledge into the live backend.\n  start it first: `%s start`", branding.CLI, branding.CLI)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	backendURL := fmt.Sprintf("http://localhost:%d", cfg.Backend.HTTPPort)
	issuer := fmt.Sprintf("http://localhost:%d/realms/%s", cfg.Keycloak.HTTPPort, cfg.Keycloak.Realm)
	cred, err := agent.NewCredential(ctx, issuer, branding.CLI, *user, *pass)
	if err != nil {
		return fmt.Errorf("login: %w\n  hint: run `%s dev-auth` first (the shipped realm has no login user)", err, branding.CLI)
	}
	token, err := cred.Token(ctx)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, backendURL+"/api/admin/demo/seed", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("seed knowledge: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		var confl struct {
			State struct {
				Investigations int `json:"investigations"`
				SOPs           int `json:"sops"`
			} `json:"state"`
		}
		_ = json.Unmarshal(body, &confl)
		return fmt.Errorf("this install already has data (%d investigations, %d SOPs) — `%s demo seed` only runs on a fresh install.\n  wipe it first with `%s demo reset` (destroys everything), or seed a fresh install",
			confl.State.Investigations, confl.State.SOPs, branding.CLI, branding.CLI)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("seed knowledge: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var seeded struct {
		Cases int
	}
	_ = json.Unmarshal(body, &seeded)

	// Knowledge is in. Now materialize the fixtures + merged capability/action
	// config beside the config, point the config at them, and flip the demo
	// switch so the fixture guard admits them on next boot.
	seed, err := runtime.SeedDemo(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("materialize demo fixtures/config: %w", err)
	}
	cfg.Capability.ConfigPath = seed.CapabilityConfig
	cfg.Capability.FixtureRoot = seed.FixtureRoot
	cfg.Demo.Enabled = true
	if err := config.Overwrite(cfg, path); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Printf("%s demo seeded.\n", branding.CLI)
	fmt.Printf("  knowledge: %d prior cases loaded (recalled by similarity during investigations)\n", seeded.Cases)
	fmt.Printf("  scenario:  %s  (fixtures at %s)\n", seed.Scenario, seed.FixtureRoot)
	fmt.Printf("  sop docs:  staged at %s — import them LIVE during the demo (workbench: \"Import SOPs…\")\n", seed.SOPDocs)
	fmt.Printf("  config:    demo.enabled = true, capability wired at %s\n", seed.CapabilityConfig)
	fmt.Println()
	fmt.Println("Restart the stack to activate the demo capabilities:")
	fmt.Printf("  %s stop && %s start\n", branding.CLI, branding.CLI)
	fmt.Printf("\nWhen you're done, `%s demo reset` wipes the demo world back to a clean install.\n", branding.CLI)
	return nil
}

// runDemoReset wipes the install back to a clean, empty state: it drops the
// reckon databases (by removing the embedded-Postgres data directory, which
// re-initializes empty on next boot) and Temporal's durable store, and removes
// the seeded fixtures + demo capability config, then flips demo.enabled off. It
// is a stack-DOWN operation (it deletes on-disk database state) and refuses on a
// non-demo install unless --force, so it can never nuke real work by accident.
// Keycloak (auth) and the secret store are left intact.
func runDemoReset(args []string) error {
	fl := flag.NewFlagSet("demo reset", flag.ContinueOnError)
	force := fl.Bool("force", false, "reset even if this is not a demo install (wipes ALL data)")
	if err := fl.Parse(args); err != nil {
		return err
	}

	path, err := config.DefaultPath()
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if !cfg.Demo.Enabled && !*force {
		return fmt.Errorf("this install is not a demo (demo.enabled is false).\n  `%s demo reset` wipes ALL data — pass --force to reset a non-demo install", branding.CLI)
	}
	// Deleting the database files under a running Postgres corrupts the cluster —
	// require the stack down.
	if backendReachable(cfg) {
		return fmt.Errorf("stop the stack before `%s demo reset` (it wipes the databases on disk): `%s stop`", branding.CLI, branding.CLI)
	}

	// Nuke the data. Postgres re-inits an empty cluster on the next boot, so
	// removing its data dir is the cleanest total wipe — no per-table archaeology
	// against an event-sourced log. Temporal's SQLite store goes too so no stale
	// workflow history references the wiped aggregates. Keycloak + secrets stay.
	base := filepath.Dir(path)
	targets := []string{
		filepath.Join(cfg.Data.Dir, "pg", "data"), // reckon_main + reckon_knowledge
		filepath.Join(cfg.Data.Dir, "temporal", "data.sqlite"),
		filepath.Join(cfg.Data.Dir, "archive"), // demo export bundles
		filepath.Join(base, "fixtures"),        // seeded fixture scenarios
		filepath.Join(base, "capability"),      // seeded demo tenant config
		filepath.Join(base, "sops"),            // staged SOP docs for live import
	}
	for _, t := range targets {
		if err := os.RemoveAll(t); err != nil {
			return fmt.Errorf("remove %s: %w", t, err)
		}
	}

	// Return the config to a clean, fixture-free real install.
	cfg.Demo.Enabled = false
	cfg.Capability.ConfigPath = ""
	cfg.Capability.FixtureRoot = "fixtures"
	if err := config.Overwrite(cfg, path); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Printf("%s demo reset — all investigations, knowledge, and fixtures wiped.\n", branding.CLI)
	fmt.Printf("  databases will re-initialize empty on next boot; Keycloak (auth) untouched.\n")
	fmt.Printf("\nNext `%s start` comes up on a clean, real install.\n", branding.CLI)
	return nil
}

// backendReachable probes the backend's unauthenticated health endpoint with a
// short timeout — true means the stack is up.
func backendReachable(cfg config.Config) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/healthz", cfg.Backend.HTTPPort))
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
