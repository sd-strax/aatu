package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sd-strax/reckon/aggregate"
	"github.com/sd-strax/reckon/authz"
	"github.com/sd-strax/reckon/internal/pgmigrate"
)

// Shared across all server integration tests in this package.
var (
	testPg      *embeddedpostgres.EmbeddedPostgres
	testDB      *sql.DB
	testReady   bool
	testHandler *aggregate.Handler

	testIssuerSrv *httptest.Server
	testRSAKey    *rsa.PrivateKey
	testKID       = "server-test-key"
)

func TestMain(m *testing.M) {
	// flag.Parse so testing.Short() works before m.Run.
	flag.Parse()

	if testing.Short() {
		os.Exit(m.Run())
	}

	dir, err := os.MkdirTemp("", "server-test-pg-*")
	if err != nil {
		log.Fatalf("temp dir: %v", err)
	}
	// `defer` is unsafe here — log.Fatalf calls os.Exit which skips
	// deferred functions. Use a named cleanup we can call before any
	// fatal exit path.
	cleanupDir := func() { _ = os.RemoveAll(dir) }

	testPg = embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(15437).
		RuntimePath(filepath.Join(dir, "runtime")).
		DataPath(filepath.Join(dir, "data")).
		Username("test").
		Password("test").
		Database("reckon_test"))
	if err := testPg.Start(); err != nil {
		cleanupDir()
		log.Fatalf("embedded postgres: %v", err)
	}

	dsn := "host=localhost port=15437 user=test password=test dbname=reckon_test sslmode=disable"
	if err := pgmigrate.Run(dsn, aggregate.Migrations(), "reckon_main"); err != nil {
		_ = testPg.Stop()
		cleanupDir()
		log.Fatalf("migrate: %v", err)
	}

	testDB, err = sql.Open("postgres", dsn)
	if err != nil {
		_ = testPg.Stop()
		cleanupDir()
		log.Fatalf("sql.Open: %v", err)
	}
	testHandler = aggregate.NewHandler(aggregate.NewStore(testDB), aggregate.InvestigationCurrentProjector{})

	// Mock OIDC issuer that signs RS256 tokens. Used by every test that
	// needs to drive an authenticated request through the router.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		_ = testPg.Stop()
		cleanupDir()
		log.Fatalf("rsa key: %v", err)
	}
	testRSAKey = priv
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   testIssuerSrv.URL,
			"jwks_uri": testIssuerSrv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA", "use": "sig", "alg": "RS256", "kid": testKID,
					"n": base64URLEncode(priv.N.Bytes()),
					"e": base64URLEncode(big.NewInt(int64(priv.E)).Bytes()),
				},
			},
		})
	})
	testIssuerSrv = httptest.NewServer(mux)

	testReady = true
	code := m.Run()

	testIssuerSrv.Close()
	_ = testDB.Close()
	_ = testPg.Stop()
	cleanupDir()
	os.Exit(code)
}

func resetInvestigations(t *testing.T) {
	t.Helper()
	if !testReady {
		t.Skip("integration setup unavailable")
	}
	if _, err := testDB.Exec(`TRUNCATE events, investigation_current`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func mintToken(t *testing.T, override map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":                testIssuerSrv.URL,
		"sub":                "test-subject",
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
		"preferred_username": "alice",
		"realm_access":       map[string]any{"roles": []string{"analyst"}},
	}
	for k, v := range override {
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKID
	signed, err := tok.SignedString(testRSAKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func newTestBackend(t *testing.T) *Backend {
	t.Helper()
	v, err := authz.NewVerifier(context.Background(), authz.VerifierConfig{
		Issuer:            testIssuerSrv.URL,
		SkipClientIDCheck: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	b := &Backend{
		cfg: BackendConfig{
			HTTPPort: 0, // unused for in-process tests
			Handler:  testHandler,
		},
		verifier: v,
	}
	return b
}

// --- /healthz: still works unauthenticated -----------------------------------

func TestHealthzIsPublic(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; want 200", resp.StatusCode)
	}
}

// --- A.6 done-bar: 401 without token, 200 with valid token, 403 without role.

func TestAPIRoute_401WithoutToken(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", resp.StatusCode)
	}
}

func TestAPIRoute_200WithValidToken(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	token := mintToken(t, nil) // analyst role by default
	req, _ := http.NewRequest("GET", srv.URL+"/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; want 200; body = %s", resp.StatusCode, readBody(resp))
	}
	var me MeResponse
	_ = json.NewDecoder(resp.Body).Decode(&me)
	if me.Subject != "test-subject" {
		t.Errorf("/me Subject = %q; want test-subject", me.Subject)
	}
	if !contains(me.Roles, "analyst") {
		t.Errorf("/me Roles = %v; want analyst included", me.Roles)
	}
}

func TestAPIRoute_403WithoutRequiredRole(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	// Token has only `viewer` role; POST /api/investigations requires
	// `analyst`. Expect 403 with required_roles surfaced.
	token := mintToken(t, map[string]any{
		"realm_access": map[string]any{"roles": []string{"viewer"}},
	})

	body := bytes.NewBufferString(`{"title":"PHISH-001"}`)
	req, _ := http.NewRequest("POST", srv.URL+"/api/investigations", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d; want 403", resp.StatusCode)
	}
	var errBody map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&errBody)
	required, _ := errBody["required_roles"].([]any)
	if len(required) == 0 || required[0] != string(authz.RoleAnalyst) {
		t.Errorf("required_roles = %v; want [%q]", required, authz.RoleAnalyst)
	}
}

// --- CreateInvestigation end-to-end through the aggregate Handler -----------

func TestCreateInvestigation_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	token := mintToken(t, nil) // analyst role
	body := bytes.NewBufferString(`{"title":"PHISH-2026-0042"}`)
	req, _ := http.NewRequest("POST", srv.URL+"/api/investigations", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d; want 201; body = %s", resp.StatusCode, readBody(resp))
	}
	var created CreateInvestigationResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Title != "PHISH-2026-0042" {
		t.Errorf("Title = %q", created.Title)
	}
	if created.NewSequenceNo != 1 {
		t.Errorf("NewSequenceNo = %d; want 1", created.NewSequenceNo)
	}
	if _, err := uuid.Parse(created.AggregateID); err != nil {
		t.Errorf("AggregateID not a UUID: %q", created.AggregateID)
	}

	// Now GET /api/investigations should return the new one.
	req, _ = http.NewRequest("GET", srv.URL+"/api/investigations", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("list status = %d; want 200", resp.StatusCode)
	}
	var list struct {
		Investigations []InvestigationView `json:"investigations"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	if len(list.Investigations) != 1 {
		t.Errorf("list len = %d; want 1", len(list.Investigations))
	}

	// And GET /api/investigations/{id} returns the single row.
	req, _ = http.NewRequest("GET", srv.URL+"/api/investigations/"+created.AggregateID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("get status = %d; want 200", resp.StatusCode)
	}
	var single InvestigationView
	_ = json.NewDecoder(resp.Body).Decode(&single)
	if single.Title != "PHISH-2026-0042" {
		t.Errorf("get Title = %q", single.Title)
	}
}

func TestGetInvestigation_NotFoundIs404(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	token := mintToken(t, nil)
	req, _ := http.NewRequest("GET", srv.URL+"/api/investigations/"+uuid.New().String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d; want 404", resp.StatusCode)
	}
}

func TestGetInvestigation_BadIDIs400(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	token := mintToken(t, nil)
	req, _ := http.NewRequest("GET", srv.URL+"/api/investigations/not-a-uuid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", resp.StatusCode)
	}
}

func TestCreateInvestigation_EmptyTitleIs400(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	resetInvestigations(t)
	b := newTestBackend(t)
	srv := httptest.NewServer(b.buildRouter(b.verifier))
	defer srv.Close()

	token := mintToken(t, nil)
	body := bytes.NewBufferString(`{"title":"  "}`)
	req, _ := http.NewRequest("POST", srv.URL+"/api/investigations", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", resp.StatusCode)
	}
}

// --- helpers -----------------------------------------------------------------

func readBody(r *http.Response) string {
	buf := make([]byte, 4096)
	n, _ := r.Body.Read(buf)
	return string(buf[:n])
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// base64URLEncode: same minimal subset used by the authz tests. Re-emitted
// here so this test file is self-contained without exporting it.
func base64URLEncode(b []byte) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := []byte{}
	for i := 0; i+3 <= len(b); i += 3 {
		out = append(out,
			charset[b[i]>>2],
			charset[((b[i]&0x03)<<4)|(b[i+1]>>4)],
			charset[((b[i+1]&0x0f)<<2)|(b[i+2]>>6)],
			charset[b[i+2]&0x3f],
		)
	}
	switch rem := len(b) % 3; rem {
	case 1:
		out = append(out, charset[b[len(b)-1]>>2], charset[(b[len(b)-1]&0x03)<<4])
	case 2:
		out = append(out,
			charset[b[len(b)-2]>>2],
			charset[((b[len(b)-2]&0x03)<<4)|(b[len(b)-1]>>4)],
			charset[(b[len(b)-1]&0x0f)<<2],
		)
	}
	return string(out)
}

// Compile-time guard against accidentally importing fmt without using it.
var _ = fmt.Sprintf
