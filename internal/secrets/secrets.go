// Package secrets is the installation secret store: per-install secrets that the
// DEPLOYER step (`reckon init`) provisions and the operator/runtime path plus
// dev tooling consume. Secrets live under <data>/secrets as 0600 files, never in
// the config (which stays non-sensitive and copy-safe). The deployer/operator/
// user role split and why secrets are born at deploy time — not invented at
// runtime — are in implementation/jwt-claims.md.
package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Well-known secret names (the file basenames under <data>/secrets).
const (
	// NameKeycloakAdmin is the Keycloak master-realm bootstrap admin password.
	NameKeycloakAdmin = "keycloak-admin-password"
	// NamePostgres is the bundled Postgres role password (user `reckon`).
	NamePostgres = "postgres-password"
)

// Env-override variable names. Set these to inject a secret at runtime from an
// external secret manager (systemd EnvironmentFile, k8s Secret, Vault) instead
// of the on-disk store — the operator/hardened-deploy path, where nothing rests
// in a reckon file. Consumers resolve with env taking precedence over the store.
const (
	// EnvKeycloakAdmin overrides NameKeycloakAdmin.
	EnvKeycloakAdmin = "KC_ADMIN_PW"
	// EnvPostgres overrides NamePostgres.
	EnvPostgres = "RECKON_PG_PASSWORD"
)

// Resolve returns a secret with precedence: the env override (if set) then the
// store. found=false when neither provides it. This is the operator-consume
// path — an injected env value wins so a hardened deployment need never write
// the secret to disk.
func (s *Store) Resolve(envVar, name string) (value string, found bool, err error) {
	if v := strings.TrimSpace(os.Getenv(envVar)); v != "" {
		return v, true, nil
	}
	return s.Get(name)
}

// Store is one installation's secret store, rooted at a directory. Nothing is
// created until a secret is written.
type Store struct{ dir string }

// Open returns the store rooted at <dataDir>/secrets.
func Open(dataDir string) *Store {
	return &Store{dir: filepath.Join(dataDir, "secrets")}
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

// Get returns a stored secret's value and true, or "" and false if it has not
// been provisioned.
func (s *Store) Get(name string) (string, bool, error) {
	b, err := os.ReadFile(s.path(name))
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read secret %q: %w", name, err)
	}
	return strings.TrimSpace(string(b)), true, nil
}

// EnsureValue provisions name with the supplied value if it is absent, then
// returns the effective value and whether it created it. An existing secret is
// returned UNCHANGED — provisioning never rotates, matching `reckon init`'s
// idempotence. Rotation is a separate, explicit act.
func (s *Store) EnsureValue(name, value string) (string, bool, error) {
	if existing, ok, err := s.Get(name); err != nil {
		return "", false, err
	} else if ok {
		return existing, false, nil
	}
	if err := s.write(name, value); err != nil {
		return "", false, err
	}
	return value, true, nil
}

// EnsureRandom provisions name with a fresh strong random value if absent,
// otherwise returns the existing one (created=false).
func (s *Store) EnsureRandom(name string) (string, bool, error) {
	if existing, ok, err := s.Get(name); err != nil {
		return "", false, err
	} else if ok {
		return existing, false, nil
	}
	v, err := randomToken(24)
	if err != nil {
		return "", false, err
	}
	return s.EnsureValue(name, v)
}

// write persists value 0600 (dir 0700), overwriting. Callers gate on existence
// via Ensure*; this is the raw writer.
func (s *Store) write(name, value string) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create secret store dir: %w", err)
	}
	if err := os.WriteFile(s.path(name), []byte(value+"\n"), 0o600); err != nil {
		return fmt.Errorf("write secret %q: %w", name, err)
	}
	return nil
}

// randomToken returns a URL-safe base64 string of n random bytes.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
