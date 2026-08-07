package supervisor

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/sd-strax/reckon/internal/branding"
)

// jreVersion and keycloakVersion pin the bundled IdP distribution. Bumping
// either is a deliberate decision.
const (
	jreVersion      = "17.0.13+11"
	keycloakVersion = "26.0.7"
)

//go:embed keycloak_realm.json
var defaultRealmJSON []byte

// KeycloakConfig configures the bundled Keycloak IdP.
type KeycloakConfig struct {
	// DataDir is the root for Keycloak's on-disk installation. Subdirs:
	//   jre/      Temurin JRE 17 (extracted)
	//   server/   Keycloak Quarkus distribution (extracted)
	//   logs/     Keycloak stdout/stderr
	// Keycloak's persistent STATE (realms, users, sessions) lives in the
	// supervised Postgres (DBPort/DBName below), not on disk — so this dir is
	// pure binaries + logs, and the binaries/data split (05 §12.4) holds.
	DataDir string

	// HTTPPort is the Keycloak HTTP listener. Default 8543 (non-standard to
	// avoid colliding with the common 8080).
	HTTPPort int

	// ManagementPort is the Keycloak management/health endpoint. Default 9543.
	ManagementPort int

	// RealmName is the bootstrap realm imported on first start. Default branding.CLI.
	RealmName string

	// AdminPassword is the master-realm bootstrap admin's password, provisioned
	// by the deployer step (`reckon init`) and injected by runtime — the
	// component consumes it, never generates it. Required; Start fails without it.
	AdminPassword string

	// DBPort is the localhost port of the supervised Postgres holding Keycloak's
	// state database. Required; Start fails without it. The supervisor starts
	// Postgres before Keycloak (registration order), so the database is up and
	// created (runtime lists DBName in the Postgres component's Databases) by
	// the time this component boots.
	DBPort uint32

	// DBName is the Keycloak state database. Default "reckon_keycloak".
	// Keycloak owns its schema (it migrates the empty database itself on first
	// contact); reckon never migrates or reads it — except the bootstrap marker
	// table this component keeps there (see ensureBootstrapAdmin).
	DBName string

	// DBUser / DBPassword authenticate to the supervised Postgres. DBUser
	// defaults to "reckon" (the embedded instance's role); DBPassword is the
	// same provisioned install secret the Postgres component consumes.
	// DBPassword is required; Start fails without it.
	DBUser     string
	DBPassword string
}

// Keycloak is a Component wrapping the Keycloak Quarkus distribution.
//
// First-run cost: ~50–100 MB Temurin JRE + ~150 MB Keycloak download, ~10s
// JVM + Keycloak boot. Subsequent runs ~10–15s warm.
//
// Air-gap compatibility: if DataDir is pre-populated (e.g., via `make bundle`
// or a delivered tarball), no downloads happen. The supervisor's behavior is
// the same; only the source of the binaries differs.
type Keycloak struct {
	cfg KeycloakConfig

	mu   sync.Mutex // guards cmd/logF; Health runs concurrently with watcher Stop/Start
	cmd  *exec.Cmd
	logF *os.File
}

// healthHTTPClient bounds every Keycloak health/readiness probe. Probes run
// on the watcher goroutine and in /status requests, where an unbounded
// http.DefaultClient call against a wedged management port would hang the
// caller indefinitely.
var healthHTTPClient = &http.Client{Timeout: 5 * time.Second}

// The realm's session/token lifetimes (seconds). MUST match
// keycloak_realm.json (guarded by TestRealm_TokenLifetimes): the JSON covers
// fresh imports, convergeRealmLifetimes heals existing installs. The load-
// bearing invariant: the SSO idle timeout must comfortably exceed the access
// token lifespan, or refresh tokens die (session idled out) before clients
// ever attempt their just-before-expiry refresh — forcing a fresh login every
// session.
const (
	realmAccessTokenLifespan = 3600    // 1h — role/claim freshness
	realmSSOIdleTimeout      = 1209600 // 14d — refresh survives a hiatus of a fortnight
	realmSSOMaxLifespan      = 2592000 // 30d — absolute re-auth backstop
)

// NewKeycloak constructs the Keycloak component (not yet started).
// Defaults: HTTPPort=8543, ManagementPort=9543, RealmName=branding.CLI,
// DataDir=$HOME/<branding.DataDir>/keycloak.
func NewKeycloak(cfg KeycloakConfig) *Keycloak {
	if cfg.HTTPPort == 0 {
		cfg.HTTPPort = 8543
	}
	if cfg.ManagementPort == 0 {
		cfg.ManagementPort = 9543
	}
	if cfg.RealmName == "" {
		cfg.RealmName = branding.CLI
	}
	if cfg.DataDir == "" {
		home, _ := os.UserHomeDir()
		cfg.DataDir = filepath.Join(home, branding.DataDir, "keycloak")
	}
	if cfg.DBName == "" {
		cfg.DBName = "reckon_keycloak"
	}
	if cfg.DBUser == "" {
		cfg.DBUser = "reckon"
	}
	return &Keycloak{cfg: cfg}
}

// Name returns "keycloak".
func (k *Keycloak) Name() string { return "keycloak" }

// Start ensures the JRE + Keycloak distribution are present (downloading if
// missing), installs the realm-import JSON, bootstraps a master-realm admin
// user on first install, spawns the Keycloak JVM, and polls the management
// /health/ready endpoint until it responds. Keycloak's state lives in the
// supervised Postgres, which the supervisor has already started (registration
// order) — a missing/unreachable database fails Start rather than silently
// falling back to the embedded H2.
func (k *Keycloak) Start(ctx context.Context) error {
	if k.cfg.DBPort == 0 || k.cfg.DBPassword == "" {
		return fmt.Errorf("keycloak: no state database configured (DBPort + DBPassword required — run `%s init`)", branding.CLI)
	}
	if err := k.ensureBinaries(ctx); err != nil {
		return err
	}
	if err := k.installRealmFile(); err != nil {
		return err
	}
	if err := k.ensureBootstrapAdmin(ctx); err != nil {
		return err
	}
	if err := k.spawn(); err != nil {
		return err
	}
	if err := k.waitForReady(ctx); err != nil {
		_ = k.kill()
		return err
	}
	k.convergeRealmLifetimes(ctx)
	return nil
}

// convergeRealmLifetimes heals an installed realm's session/token lifetimes to
// the shipped defaults. --import-realm only reads keycloak_realm.json when the
// realm doesn't exist, so a lifetime fix there never reaches existing installs
// on its own; this runs every boot and is a no-op once the values match. The
// values must stay in lockstep with keycloak_realm.json. Best-effort: a
// failure logs and continues — a stale lifetime degrades session longevity,
// not correctness, and must not take the IdP down with it.
//
// The invariant that matters: the SSO idle timeout must comfortably exceed
// accessTokenLifespan, or every refresh token dies (session idled out) before
// clients ever attempt their just-before-expiry refresh — the "why do I have
// to log in every time" failure mode.
func (k *Keycloak) convergeRealmLifetimes(ctx context.Context) {
	admin := NewKeycloakAdmin(fmt.Sprintf("http://localhost:%d", k.cfg.HTTPPort), k.cfg.RealmName)
	if err := admin.Login(ctx, "admin", k.cfg.AdminPassword); err != nil {
		log.Printf("keycloak: realm-lifetime convergence skipped (admin login: %v)", err)
		return
	}
	changed, err := admin.EnsureTokenLifetimes(ctx, realmAccessTokenLifespan, realmSSOIdleTimeout, realmSSOMaxLifespan)
	if err != nil {
		log.Printf("keycloak: realm-lifetime convergence failed: %v", err)
		return
	}
	if changed {
		log.Printf("keycloak: realm %s session lifetimes converged to shipped defaults (sso idle 14d, max 30d)", k.cfg.RealmName)
	}
}

// Stop sends SIGTERM, waits up to ctx's deadline (or 30s default) for clean
// exit, then SIGKILLs. Idempotent.
func (k *Keycloak) Stop(ctx context.Context) error {
	k.mu.Lock()
	cmd := k.cmd
	logF := k.logF
	k.cmd = nil
	k.logF = nil
	k.mu.Unlock()
	if cmd == nil {
		return nil
	}
	defer func() {
		if logF != nil {
			_ = logF.Close()
		}
	}()

	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	deadline := 30 * time.Second
	if d, ok := ctx.Deadline(); ok {
		if remaining := time.Until(d); remaining > 0 && remaining < deadline {
			deadline = remaining
		}
	}

	select {
	case <-done:
		return nil
	case <-time.After(deadline):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		return fmt.Errorf("keycloak did not stop cleanly within %s; killed", deadline)
	}
}

// Health probes the management /health/ready endpoint.
func (k *Keycloak) Health(ctx context.Context) HealthStatus {
	k.mu.Lock()
	cmd := k.cmd
	k.mu.Unlock()
	if cmd == nil {
		return HealthStatus{Ready: false, Message: "not started"}
	}
	url := fmt.Sprintf("http://localhost:%d/health/ready", k.cfg.ManagementPort)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return HealthStatus{Ready: false, Message: err.Error()}
	}
	resp, err := healthHTTPClient.Do(req)
	if err != nil {
		return HealthStatus{Ready: false, Message: err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 {
		return HealthStatus{Ready: false, Message: fmt.Sprintf("health %d", resp.StatusCode)}
	}
	return HealthStatus{
		Ready:   true,
		Message: fmt.Sprintf("http :%d, realm %s", k.cfg.HTTPPort, k.cfg.RealmName),
	}
}

// IssuerURL returns the OIDC issuer URL for the configured realm. Stable
// across restarts as long as HTTPPort and RealmName don't change.
func (k *Keycloak) IssuerURL() string {
	return fmt.Sprintf("http://localhost:%d/realms/%s", k.cfg.HTTPPort, k.cfg.RealmName)
}

// --- internals ---------------------------------------------------------------

func (k *Keycloak) jreDir() string    { return filepath.Join(k.cfg.DataDir, "jre") }
func (k *Keycloak) serverDir() string { return filepath.Join(k.cfg.DataDir, "server") }

// javaHome is what kc.sh expects in $JAVA_HOME. macOS Temurin nests the
// JRE under Contents/Home/; Linux Temurin extracts straight to the root.
func (k *Keycloak) javaHome() string {
	if goruntime.GOOS == "darwin" {
		return filepath.Join(k.jreDir(), "Contents", "Home")
	}
	return k.jreDir()
}

// keycloakLauncher is the kc.sh script that owns CLASSPATH + JAVA_OPTS setup.
// Running `java -jar quarkus-run.jar` directly skips this and breaks
// Environment.getHomePath().
func (k *Keycloak) keycloakLauncher() string {
	return filepath.Join(k.serverDir(), "bin", "kc.sh")
}

func (k *Keycloak) ensureBinaries(ctx context.Context) error {
	jreURL, err := temurinJREURL()
	if err != nil {
		return err
	}
	jreMarker := relativeJavaBin()
	if err := downloadAndExtractTarGz(ctx, jreURL, k.jreDir(), jreMarker, 1); err != nil {
		return fmt.Errorf("ensure JRE: %w", err)
	}

	kcURL := keycloakTarballURL()
	kcMarker := filepath.Join("bin", "kc.sh")
	if err := downloadAndExtractTarGz(ctx, kcURL, k.serverDir(), kcMarker, 1); err != nil {
		return fmt.Errorf("ensure Keycloak: %w", err)
	}
	// kc.sh must be executable; preserve mode from tarball but defensive chmod.
	if err := os.Chmod(k.keycloakLauncher(), 0o755); err != nil {
		return fmt.Errorf("chmod kc.sh: %w", err)
	}
	return nil
}

// relativeJavaBin returns the path to the `java` binary relative to the JRE
// install root (after stripComponents=1 has stripped the tarball's top-level
// directory).
func relativeJavaBin() string {
	if goruntime.GOOS == "darwin" {
		return filepath.Join("Contents", "Home", "bin", "java")
	}
	return filepath.Join("bin", "java")
}

// --- state database ----------------------------------------------------------

// jdbcURL is the JDBC form of the state-database address, for Keycloak itself.
func (k *Keycloak) jdbcURL() string {
	return fmt.Sprintf("jdbc:postgresql://localhost:%d/%s", k.cfg.DBPort, k.cfg.DBName)
}

// libpqDSN is the libpq form of the same address, for this component's own
// bootstrap-marker check.
func (k *Keycloak) libpqDSN() string {
	return fmt.Sprintf("host=localhost port=%d user=%s password=%s dbname=%s sslmode=disable",
		k.cfg.DBPort, k.cfg.DBUser, k.cfg.DBPassword, k.cfg.DBName)
}

// dbEnv is the KC_DB_* environment both `bootstrap-admin` and `start-dev`
// receive — env rather than argv so the DB password never appears in a process
// listing.
func (k *Keycloak) dbEnv() []string {
	return []string{
		"KC_DB=postgres",
		"KC_DB_URL=" + k.jdbcURL(),
		"KC_DB_USERNAME=" + k.cfg.DBUser,
		"KC_DB_PASSWORD=" + k.cfg.DBPassword,
	}
}

// bootstrapMarkerTable is this component's one table in the Keycloak state
// database. Its EXISTENCE is the marker (no rows needed): it shares the
// database's lifetime, so wiping/recreating the database drops the marker with
// it and bootstrap re-runs — the same self-healing property the old
// marker-file-next-to-H2 gave, relocated to where the state now lives.
const bootstrapMarkerTable = "reckon_admin_bootstrap"

// ensureBootstrapAdmin creates the master-realm admin user (username `admin`)
// so the Keycloak admin console and the Admin REST API are usable. Idempotent
// via the marker table in the state database (see bootstrapMarkerTable).
//
// The password is NOT a hardcoded default: it comes from cfg.AdminPassword,
// provisioned by the deployer step (`reckon init`) into the install secret store
// and injected by runtime. The component only consumes it. The app-side login
// principal is separate again (`reckon dev-auth`, keycloak_realm.json ships no
// user) — three distinct Keycloak authentication contexts.
func (k *Keycloak) ensureBootstrapAdmin(ctx context.Context) error {
	if k.cfg.AdminPassword == "" {
		return fmt.Errorf("keycloak: no admin password provisioned (run `%s init`)", branding.CLI)
	}
	db, err := sql.Open("postgres", k.libpqDSN())
	if err != nil {
		return fmt.Errorf("keycloak: open state database: %w", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	var marked bool
	if err := db.QueryRowContext(ctx,
		"SELECT to_regclass($1) IS NOT NULL", "public."+bootstrapMarkerTable,
	).Scan(&marked); err != nil {
		return fmt.Errorf("keycloak: check bootstrap marker (is the supervised Postgres up?): %w", err)
	}
	if marked {
		return nil
	}

	// bootstrap-admin runs Keycloak's store layer offline: on a fresh database
	// it first applies Keycloak's own schema, then writes the admin user.
	cmd := exec.CommandContext(ctx, k.keycloakLauncher(),
		"bootstrap-admin", "user",
		"--username", "admin",
		"--password:env", "KC_ADMIN_PW",
		"--no-prompt",
	)
	cmd.Env = append(os.Environ(),
		"JAVA_HOME="+k.javaHome(),
		"KC_ADMIN_PW="+k.cfg.AdminPassword,
	)
	cmd.Env = append(cmd.Env, k.dbEnv()...)
	if out, err := cmd.CombinedOutput(); err != nil {
		// bootstrap-admin may legitimately fail if an admin already exists
		// in some edge cases (e.g., partial wipe). Log and continue — the
		// subsequent start-dev will surface any real auth issue.
		log.Printf("keycloak bootstrap-admin returned non-zero: %v\n%s", err, out)
	} else {
		log.Printf("keycloak: master-realm admin bootstrapped (user admin; password from the install secret store)")
	}

	if _, err := db.ExecContext(ctx,
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (bootstrapped_at timestamptz NOT NULL DEFAULT now())", bootstrapMarkerTable),
	); err != nil {
		return fmt.Errorf("keycloak: write bootstrap marker: %w", err)
	}
	return nil
}

func (k *Keycloak) installRealmFile() error {
	importDir := filepath.Join(k.serverDir(), "data", "import")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		return fmt.Errorf("create import dir: %w", err)
	}
	target := filepath.Join(importDir, branding.CLI+"-realm.json")
	if err := os.WriteFile(target, defaultRealmJSON, 0o644); err != nil {
		return fmt.Errorf("write realm file: %w", err)
	}
	return nil
}

func (k *Keycloak) spawn() error {
	logsDir := filepath.Join(k.cfg.DataDir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		return fmt.Errorf("create logs dir: %w", err)
	}
	logF, err := os.OpenFile(filepath.Join(logsDir, "keycloak.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	args := []string{
		"start-dev",
		"--http-enabled=true",
		"--http-port=" + strconv.Itoa(k.cfg.HTTPPort),
		"--http-management-port=" + strconv.Itoa(k.cfg.ManagementPort),
		"--hostname=localhost",
		"--hostname-strict=false",
		"--health-enabled=true",
		"--import-realm",
	}
	cmd := exec.Command(k.keycloakLauncher(), args...)
	cmd.Env = append(os.Environ(), "JAVA_HOME="+k.javaHome())
	cmd.Env = append(cmd.Env, k.dbEnv()...)
	cmd.Stdout = logF
	cmd.Stderr = logF

	if err := cmd.Start(); err != nil {
		_ = logF.Close()
		return fmt.Errorf("spawn keycloak: %w", err)
	}
	k.mu.Lock()
	k.cmd = cmd
	k.logF = logF
	k.mu.Unlock()
	return nil
}

func (k *Keycloak) waitForReady(ctx context.Context) error {
	url := fmt.Sprintf("http://localhost:%d/health/ready", k.cfg.ManagementPort)
	// Keycloak's first boot takes 10–20s warm; the JVM + Quarkus init are slow.
	// Generous outer cap so first-run smoke tests work.
	deadline := time.Now().Add(90 * time.Second)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("keycloak /health/ready did not respond within 90s; see %s/logs/keycloak.log", k.cfg.DataDir)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := healthHTTPClient.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (k *Keycloak) kill() error {
	k.mu.Lock()
	cmd := k.cmd
	logF := k.logF
	k.cmd = nil
	k.logF = nil
	k.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil {
		return err
	}
	_, _ = cmd.Process.Wait()
	if logF != nil {
		_ = logF.Close()
	}
	return nil
}

// --- URLs --------------------------------------------------------------------

func temurinJREURL() (string, error) {
	var osTag, archTag string
	switch goruntime.GOOS {
	case "darwin":
		osTag = "mac"
	case "linux":
		osTag = "linux"
	default:
		return "", fmt.Errorf("supervisor.Keycloak: unsupported OS %q (need darwin or linux for now)", goruntime.GOOS)
	}
	switch goruntime.GOARCH {
	case "amd64":
		archTag = "x64"
	case "arm64":
		archTag = "aarch64"
	default:
		return "", fmt.Errorf("supervisor.Keycloak: unsupported arch %q", goruntime.GOARCH)
	}
	// Adoptium tag URL-encodes '+' as %2B.
	tag := "jdk-17.0.13%2B11"
	file := fmt.Sprintf("OpenJDK17U-jre_%s_%s_hotspot_17.0.13_11.tar.gz", archTag, osTag)
	return "https://github.com/adoptium/temurin17-binaries/releases/download/" + tag + "/" + file, nil
}

func keycloakTarballURL() string {
	return fmt.Sprintf("https://github.com/keycloak/keycloak/releases/download/%s/keycloak-%s.tar.gz",
		keycloakVersion, keycloakVersion)
}
