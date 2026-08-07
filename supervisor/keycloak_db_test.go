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
