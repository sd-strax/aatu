package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequireAuth_RejectsMissingHeader(t *testing.T) {
	tk := newTestKeycloak(t)
	v, _ := NewVerifier(context.Background(), VerifierConfig{
		Issuer:   tk.srv.URL,
		ClientID: "reckon",
	})

	handler := RequireAuth(v)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler should not run on missing Authorization")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", w.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	if !strings.Contains(body["error"].(string), "Authorization") {
		t.Errorf("error body = %v; want to mention Authorization header", body)
	}
}

func TestRequireAuth_RejectsMalformedScheme(t *testing.T) {
	tk := newTestKeycloak(t)
	v, _ := NewVerifier(context.Background(), VerifierConfig{
		Issuer:   tk.srv.URL,
		ClientID: "reckon",
	})

	handler := RequireAuth(v)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("inner handler should not run")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d; want 401", w.Code)
	}
}

func TestRequireAuth_AcceptsValidBearerToken(t *testing.T) {
	tk := newTestKeycloak(t)
	v, _ := NewVerifier(context.Background(), VerifierConfig{
		Issuer:   tk.srv.URL,
		ClientID: "reckon",
	})
	raw := tk.mintToken(t, nil)

	var sawClaims Claims
	handler := RequireAuth(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := FromContext(r.Context())
		if !ok {
			t.Fatal("expected claims in context")
		}
		sawClaims = c
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200; body = %s", w.Code, w.Body.String())
	}
	if sawClaims.Subject != "test-subject" {
		t.Errorf("context Claims.Subject = %q; want test-subject", sawClaims.Subject)
	}
}

func TestRequireRole_DeniesMissingRole_SurfacesRequiredList(t *testing.T) {
	// Bypass RequireAuth — directly inject claims.
	c := Claims{Subject: "x", Roles: []string{RoleViewer}}
	handler := RequireRole(RoleTenantAdmin, RoleAuditor)(
		http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("inner handler should not run")
		}),
	)

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(WithClaims(req.Context(), c))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d; want 403", w.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	required, _ := body["required_roles"].([]any)
	if len(required) != 2 {
		t.Errorf("required_roles len = %d; want 2 (was %v)", len(required), body)
	}
}

func TestRequireRole_AcceptsAnyMatchingRole(t *testing.T) {
	c := Claims{Subject: "x", Roles: []string{RoleViewer}}
	handler := RequireRole(RoleViewer, RoleAnalyst)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(WithClaims(req.Context(), c))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want 200", w.Code)
	}
}

func TestRequireRole_500sWhenMisConfigured(t *testing.T) {
	// RequireRole without RequireAuth ahead of it should surface a wiring
	// error, not silently pass.
	handler := RequireRole(RoleAnalyst)(
		http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("inner handler should not run")
		}),
	)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d; want 500", w.Code)
	}
}

// End-to-end: RequireAuth composed with RequireRole.
func TestRequireAuth_Then_RequireRole(t *testing.T) {
	tk := newTestKeycloak(t)
	v, _ := NewVerifier(context.Background(), VerifierConfig{
		Issuer:   tk.srv.URL,
		ClientID: "reckon",
	})

	// Token has only `analyst` role (default mint). Endpoint requires
	// `tenant_admin`. Expect 403 with the required role surfaced.
	raw := tk.mintToken(t, nil)

	chain := RequireAuth(v)(RequireRole(RoleTenantAdmin)(
		http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			t.Fatal("inner handler should not run on 403")
		}),
	))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d; want 403; body = %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	required, _ := body["required_roles"].([]any)
	if len(required) != 1 || required[0] != RoleTenantAdmin {
		t.Errorf("required_roles = %v; want [%q]", required, RoleTenantAdmin)
	}
}
