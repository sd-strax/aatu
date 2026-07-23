package supervisor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeKeycloak is a minimal stand-in for the Keycloak Admin REST surface
// ProvisionDevAuth drives. It records the mutating calls so the test can assert
// the flow issues the right requests — coverage the real-Keycloak lifecycle test
// (make test-all) can't give quickly.
type fakeKeycloak struct {
	userExists    bool
	ropcEnabled   map[string]bool
	passwordSet   string
	rolesAssigned []string
	createdUser   bool
}

func (f *fakeKeycloak) handler() http.Handler {
	if f.ropcEnabled == nil {
		f.ropcEnabled = map[string]bool{}
	}
	const userID = "user-uuid-1"
	mux := http.NewServeMux()

	mux.HandleFunc("/realms/master/protocol/openid-connect/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "admin-token", "expires_in": 60})
	})

	mux.HandleFunc("/admin/realms/reckon/clients", func(w http.ResponseWriter, r *http.Request) {
		cid := r.URL.Query().Get("clientId")
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"id": "client-" + cid, "clientId": cid, "directAccessGrantsEnabled": f.ropcEnabled[cid]},
		})
	})
	mux.HandleFunc("/admin/realms/reckon/clients/", func(w http.ResponseWriter, r *http.Request) {
		var rep map[string]any
		_ = json.NewDecoder(r.Body).Decode(&rep)
		cid, _ := rep["clientId"].(string)
		f.ropcEnabled[cid], _ = rep["directAccessGrantsEnabled"].(bool)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/admin/realms/reckon/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			f.userExists = true
			f.createdUser = true
			w.Header().Set("Location", "/admin/realms/reckon/users/"+userID)
			w.WriteHeader(http.StatusCreated)
			return
		}
		if f.userExists {
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": userID, "username": r.URL.Query().Get("username")}})
		} else {
			_ = json.NewEncoder(w).Encode([]map[string]any{})
		}
	})
	mux.HandleFunc("/admin/realms/reckon/users/"+userID+"/reset-password", func(w http.ResponseWriter, r *http.Request) {
		var cred map[string]any
		_ = json.NewDecoder(r.Body).Decode(&cred)
		f.passwordSet, _ = cred["value"].(string)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/admin/realms/reckon/users/"+userID+"/role-mappings/realm", func(w http.ResponseWriter, r *http.Request) {
		var reps []map[string]any
		_ = json.NewDecoder(r.Body).Decode(&reps)
		for _, rep := range reps {
			if n, _ := rep["name"].(string); n != "" {
				f.rolesAssigned = append(f.rolesAssigned, n)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/admin/realms/reckon/roles/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/admin/realms/reckon/roles/")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "role-" + name, "name": name})
	})

	return mux
}

func TestProvisionDevAuth_CreatesUserEnablesROPCAndAssignsRoles(t *testing.T) {
	fake := &fakeKeycloak{}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	created, err := ProvisionDevAuth(context.Background(), DevAuthOptions{
		BaseURL:   srv.URL,
		Realm:     "reckon",
		AdminUser: "admin",
		AdminPass: "admin",
		Username:  "reckon-admin",
		Password:  "s3cret",
		Roles:     []string{"tenant_admin", "analyst"},
		ROPCFor:   []string{"reckon", "reckon-agent"},
	})
	if err != nil {
		t.Fatalf("ProvisionDevAuth: %v", err)
	}
	if !created {
		t.Error("expected created=true for a fresh user")
	}
	if !fake.ropcEnabled["reckon"] || !fake.ropcEnabled["reckon-agent"] {
		t.Errorf("ROPC not enabled on both clients: %v", fake.ropcEnabled)
	}
	if fake.passwordSet != "s3cret" {
		t.Errorf("password = %q; want s3cret", fake.passwordSet)
	}
	if got := strings.Join(fake.rolesAssigned, ","); got != "tenant_admin,analyst" {
		t.Errorf("roles assigned = %q; want tenant_admin,analyst", got)
	}
}

func TestProvisionDevAuth_ExistingUserIsUpdatedNotCreated(t *testing.T) {
	fake := &fakeKeycloak{userExists: true}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	created, err := ProvisionDevAuth(context.Background(), DevAuthOptions{
		BaseURL:  srv.URL,
		Realm:    "reckon",
		Username: "reckon-admin",
		Password: "pw",
		Roles:    []string{"analyst"},
		ROPCFor:  []string{"reckon"},
	})
	if err != nil {
		t.Fatalf("ProvisionDevAuth: %v", err)
	}
	if created {
		t.Error("expected created=false for a pre-existing user")
	}
	if fake.createdUser {
		t.Error("must not POST a new user when one already exists")
	}
}

func TestKeycloakAdmin_LoginSurfacesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	admin := NewKeycloakAdmin(srv.URL, "reckon")
	if err := admin.Login(context.Background(), "admin", "wrong"); err == nil {
		t.Fatal("expected an error on a 401 token response")
	}
}
