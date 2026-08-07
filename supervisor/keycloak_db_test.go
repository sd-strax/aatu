package supervisor

import (
	"strings"
	"testing"
)

// TestKeycloakDBDefaultsAndEnv covers the state-database wiring: defaults, the
// JDBC/libpq address forms, and the KC_DB_* environment (where the password
// travels — env, never argv).
func TestKeycloakDBDefaultsAndEnv(t *testing.T) {
	k := NewKeycloak(KeycloakConfig{DBPort: 5435, DBPassword: "s3cret"})

	if k.cfg.DBName != "reckon_keycloak" {
		t.Errorf("DBName default = %q, want reckon_keycloak", k.cfg.DBName)
	}
	if k.cfg.DBUser != "reckon" {
		t.Errorf("DBUser default = %q, want reckon", k.cfg.DBUser)
	}
	if got, want := k.jdbcURL(), "jdbc:postgresql://localhost:5435/reckon_keycloak"; got != want {
		t.Errorf("jdbcURL = %q, want %q", got, want)
	}

	env := strings.Join(k.dbEnv(), "\n")
	for _, want := range []string{
		"KC_DB=postgres",
		"KC_DB_URL=jdbc:postgresql://localhost:5435/reckon_keycloak",
		"KC_DB_USERNAME=reckon",
		"KC_DB_PASSWORD=s3cret",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("dbEnv missing %q in:\n%s", want, env)
		}
	}
}

// TestKeycloakStartRequiresDB: without a configured state database, Start must
// fail fast rather than silently falling back to embedded H2.
func TestKeycloakStartRequiresDB(t *testing.T) {
	k := NewKeycloak(KeycloakConfig{AdminPassword: "x"})
	err := k.Start(t.Context())
	if err == nil || !strings.Contains(err.Error(), "state database") {
		t.Fatalf("Start without DB config: err = %v, want state-database error", err)
	}
}

// TestKeycloakRuntimeDirSplit: with RuntimeDir set, the JRE + server live
// there (image-owned in the container shape); default stays under DataDir.
func TestKeycloakRuntimeDirSplit(t *testing.T) {
	k := NewKeycloak(KeycloakConfig{DataDir: "/data/kc", RuntimeDir: "/opt/reckon/keycloak"})
	if got := k.serverDir(); got != "/opt/reckon/keycloak/server" {
		t.Errorf("serverDir = %q, want under RuntimeDir", got)
	}
	if got := k.jreDir(); got != "/opt/reckon/keycloak/jre" {
		t.Errorf("jreDir = %q, want under RuntimeDir", got)
	}

	def := NewKeycloak(KeycloakConfig{DataDir: "/data/kc"})
	if got := def.serverDir(); got != "/data/kc/server" {
		t.Errorf("default serverDir = %q, want under DataDir", got)
	}
}
