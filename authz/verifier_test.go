package authz

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testKeycloak spins up a minimal HTTP server that pretends to be a
// Keycloak realm — serves the OIDC discovery doc and the JWKS, and lets
// callers mint signed JWTs that NewVerifier will validate.
type testKeycloak struct {
	srv        *httptest.Server
	privateKey *rsa.PrivateKey
	keyID      string
}

func newTestKeycloak(t *testing.T) *testKeycloak {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tk := &testKeycloak{privateKey: priv, keyID: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   tk.srv.URL,
			"jwks_uri": tk.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"use": "sig",
					"alg": "RS256",
					"kid": tk.keyID,
					"n":   base64URLEncode(priv.N.Bytes()),
					"e":   base64URLEncode(big.NewInt(int64(priv.E)).Bytes()),
				},
			},
		})
	})

	tk.srv = httptest.NewServer(mux)
	t.Cleanup(func() { tk.srv.Close() })
	return tk
}

// mintToken builds a signed JWT with the given claims. exp can be either
// "valid" (1 hour in the future) or "expired" (1 hour ago).
func (tk *testKeycloak) mintToken(t *testing.T, override map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":                tk.srv.URL,
		"sub":                "test-subject",
		"aud":                "aatu",
		"exp":                now.Add(time.Hour).Unix(),
		"iat":                now.Unix(),
		"preferred_username": "alice",
		"realm_access":       map[string]any{"roles": []string{"analyst"}},
	}
	for k, v := range override {
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = tk.keyID
	signed, err := tok.SignedString(tk.privateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func TestVerifier_VerifyValidToken(t *testing.T) {
	tk := newTestKeycloak(t)
	v, err := NewVerifier(context.Background(), VerifierConfig{
		Issuer:   tk.srv.URL,
		ClientID: "aatu",
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	raw := tk.mintToken(t, nil)
	claims, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "test-subject" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.PreferredUsername != "alice" {
		t.Errorf("PreferredUsername = %q", claims.PreferredUsername)
	}
	if !claims.HasRole("analyst") {
		t.Errorf("expected analyst role; got Roles=%v", claims.Roles)
	}
}

func TestVerifier_RejectsExpiredToken(t *testing.T) {
	tk := newTestKeycloak(t)
	v, _ := NewVerifier(context.Background(), VerifierConfig{
		Issuer:   tk.srv.URL,
		ClientID: "aatu",
	})

	raw := tk.mintToken(t, map[string]any{
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})
	_, err := v.Verify(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for expired token; got nil")
	}
}

func TestVerifier_RejectsBadSignature(t *testing.T) {
	tk := newTestKeycloak(t)
	v, _ := NewVerifier(context.Background(), VerifierConfig{
		Issuer:   tk.srv.URL,
		ClientID: "aatu",
	})

	raw := tk.mintToken(t, nil)
	tampered := raw + "x" // corrupt signature
	_, err := v.Verify(context.Background(), tampered)
	if err == nil {
		t.Fatal("expected error for tampered signature; got nil")
	}
}

func TestVerifier_RejectsWrongIssuer(t *testing.T) {
	tk1 := newTestKeycloak(t)
	tk2 := newTestKeycloak(t)
	// Verifier configured for tk1, token minted by tk2
	v, _ := NewVerifier(context.Background(), VerifierConfig{
		Issuer:   tk1.srv.URL,
		ClientID: "aatu",
	})
	raw := tk2.mintToken(t, map[string]any{"iss": tk2.srv.URL})
	_, err := v.Verify(context.Background(), raw)
	if err == nil {
		t.Fatal("expected error for token from wrong issuer; got nil")
	}
}

func TestVerifier_ExtractsTenantAndDelegate(t *testing.T) {
	tk := newTestKeycloak(t)
	v, _ := NewVerifier(context.Background(), VerifierConfig{
		Issuer:   tk.srv.URL,
		ClientID: "aatu",
	})

	raw := tk.mintToken(t, map[string]any{
		"tenant_id":     "tenant-42",
		"delegate_kind": "anthropic:claude-opus-4-8",
	})
	claims, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.TenantID != "tenant-42" {
		t.Errorf("TenantID = %q", claims.TenantID)
	}
	if claims.DelegateKind != "anthropic:claude-opus-4-8" {
		t.Errorf("DelegateKind = %q", claims.DelegateKind)
	}
}

// base64URLEncode is the minimal subset of base64url encoding the JWKS
// payload needs. We avoid importing encoding/base64 directly because the
// JWS conventional alphabet drops padding and uses URL-safe chars.
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
