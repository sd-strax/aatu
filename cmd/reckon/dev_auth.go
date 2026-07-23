package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/sd-strax/reckon/config"
	"github.com/sd-strax/reckon/internal/branding"
	"github.com/sd-strax/reckon/supervisor"
)

// devAuthRoles is the role set the provisioned principal receives — enough to
// exercise the whole engine locally: read/write investigations, and approve at
// both trust tiers. It mirrors the roles the realm used to ship on its bundled
// user, which is deliberately no longer in the artifact.
var devAuthRoles = []string{"tenant_admin", "analyst", "approver", "senior_approver"}

// runDevAuth provisions a local dev/CI login principal against a RUNNING
// Keycloak and enables the direct-access (ROPC) grant on the two clients.
//
// This exists because the shipped realm (supervisor/keycloak_realm.json) carries
// no credentialed account and no password grant — both are dev/CI scaffolding,
// not properties of the distributed software (implementation/jwt-claims.md). The
// workbench signs in with PKCE and only needs the *user* to exist; eval and
// `reckon investigate` additionally need ROPC, which this turns on at runtime.
//
// It is loud on purpose: it weakens the running instance's auth posture and must
// never be run against a hardened/shared deployment.
func runDevAuth(args []string) error {
	fs := flag.NewFlagSet("dev-auth", flag.ContinueOnError)
	username := fs.String("user", branding.CLI+"-admin", "principal username to provision")
	password := fs.String("password", envOr("RECKON_PASSWORD", branding.CLI), "non-temporary password to set")
	adminUser := fs.String("admin-user", envOr("KC_ADMIN_USER", "admin"), "master-realm bootstrap admin username")
	adminPass := fs.String("admin-password", envOr("KC_ADMIN_PW", "admin"), "master-realm bootstrap admin password")
	noROPC := fs.Bool("no-direct-grants", false, "provision the user but do NOT enable the ROPC grant")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	baseURL := fmt.Sprintf("http://localhost:%d", cfg.Keycloak.HTTPPort)

	opts := supervisor.DevAuthOptions{
		BaseURL:   baseURL,
		Realm:     cfg.Keycloak.Realm,
		AdminUser: *adminUser,
		AdminPass: *adminPass,
		Username:  *username,
		Password:  *password,
		Roles:     devAuthRoles,
	}
	if !*noROPC {
		opts.ROPCFor = []string{branding.CLI, branding.CLI + "-agent"}
	}

	created, err := supervisor.ProvisionDevAuth(context.Background(), opts)
	if err != nil {
		return fmt.Errorf("provisioning against %s (realm %q): %w", baseURL, cfg.Keycloak.Realm, err)
	}

	verb := "updated"
	if created {
		verb = "created"
	}
	fmt.Fprintf(os.Stderr, "dev-auth: %s principal %q with roles %v\n", verb, *username, devAuthRoles)
	if !*noROPC {
		fmt.Fprintf(os.Stderr, "dev-auth: enabled the direct-access (ROPC) grant on the %s and %s-agent clients\n", branding.CLI, branding.CLI)
	}
	fmt.Fprintf(os.Stderr, "\n  login: %s / %s   (realm %q at %s)\n", *username, *password, cfg.Keycloak.Realm, baseURL)
	fmt.Fprintln(os.Stderr, "\n⚠  dev/CI only — this weakens the running instance's auth posture. Never run it against a shared or hardened deployment.")
	return nil
}
