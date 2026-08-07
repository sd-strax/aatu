package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sd-strax/reckon/action"
	"github.com/sd-strax/reckon/internal/adapterplugin"
)

// mockFalcon is a minimal Falcon API double: /oauth2/token mints a token,
// /devices/entities/devices-actions/v2 replies per the configured script.
func mockFalcon(t *testing.T, actionStatus int, actionBody string) (*httptest.Server, *int) {
	t.Helper()
	tokenCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "sec" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		tokenCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-1","expires_in":1799}`))
	})
	mux.HandleFunc("/devices/entities/devices-actions/v2", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if an := r.URL.Query().Get("action_name"); an != "contain" && an != "lift_containment" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(actionStatus)
		_, _ = w.Write([]byte(actionBody))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &tokenCalls
}

func dispatchVia(t *testing.T, baseURL, op, device string) action.WriteResult {
	t.Helper()
	b := newBridge()
	cfg, _ := json.Marshal(adapterplugin.ConfigureParams{Config: map[string]any{
		"client_id": "cid", "client_secret": "sec", "base_url": baseURL,
	}})
	if _, werr := b.configure(cfg); werr != nil {
		t.Fatalf("configure: %v", werr)
	}
	params, _ := json.Marshal(adapterplugin.DispatchParams{
		Operation:      op,
		Params:         map[string]any{"device_id": device},
		IdempotencyKey: "act-1:" + device,
	})
	res, werr := b.dispatch(context.Background(), params)
	if werr != nil {
		t.Fatalf("dispatch wire error: %v", werr)
	}
	wr, ok := res.(action.WriteResult)
	if !ok {
		t.Fatalf("dispatch result type %T", res)
	}
	return wr
}

// TestContainSucceeds: token minted, device in resources[] → OK per target.
func TestContainSucceeds(t *testing.T) {
	srv, tokenCalls := mockFalcon(t, 202, `{"resources":[{"id":"dev-1"}],"errors":[]}`)
	wr := dispatchVia(t, srv.URL, "contain", "dev-1")
	if wr.FinalOutcome != action.OutcomeSucceeded || wr.PerTargetResults["dev-1"] != action.TargetOK {
		t.Fatalf("result = %+v, want SUCCEEDED/OK", wr)
	}
	if *tokenCalls != 1 {
		t.Errorf("token calls = %d, want 1", *tokenCalls)
	}
}

// TestContainVendorError: device absent, errors[] present, 4xx → FAIL, fatal
// class, vendor message in the detail.
func TestContainVendorError(t *testing.T) {
	srv, _ := mockFalcon(t, 403, `{"resources":[],"errors":[{"code":403,"message":"access denied: hosts:write required"}]}`)
	wr := dispatchVia(t, srv.URL, "contain", "dev-1")
	if wr.FinalOutcome != action.OutcomeFailed || wr.PerTargetResults["dev-1"] != action.TargetFail {
		t.Fatalf("result = %+v, want FAILED/FAIL", wr)
	}
	if wr.ErrorClass != action.WriteFatal {
		t.Errorf("class = %s, want FATAL (4xx)", wr.ErrorClass)
	}
}

// TestContainTransportAmbiguity: the API is unreachable → per-target UNKNOWN,
// retryable — never an inferred failure of the action itself (08 §6c).
func TestContainTransportAmbiguity(t *testing.T) {
	srv, _ := mockFalcon(t, 202, `{}`)
	url := srv.URL
	srv.Close() // now unreachable
	wr := dispatchVia(t, url, "lift_containment", "dev-9")
	if wr.PerTargetResults["dev-9"] != action.TargetUnknown {
		t.Fatalf("result = %+v, want per-target UNKNOWN", wr)
	}
	if wr.ErrorClass != action.WriteRetryable {
		t.Errorf("class = %s, want RETRYABLE", wr.ErrorClass)
	}
}

// TestTokenReuse: two dispatches, one token mint (cached until expiry).
func TestTokenReuse(t *testing.T) {
	srv, tokenCalls := mockFalcon(t, 202, `{"resources":[{"id":"dev-1"}]}`)
	_ = dispatchVia(t, srv.URL, "contain", "dev-1")
	b := newBridge()
	cfg, _ := json.Marshal(adapterplugin.ConfigureParams{Config: map[string]any{
		"client_id": "cid", "client_secret": "sec", "base_url": srv.URL,
	}})
	_, _ = b.configure(cfg)
	for range 2 {
		params, _ := json.Marshal(adapterplugin.DispatchParams{
			Operation: "contain", Params: map[string]any{"device_id": "dev-1"}, IdempotencyKey: "k",
		})
		if _, werr := b.dispatch(context.Background(), params); werr != nil {
			t.Fatal(werr)
		}
	}
	// 1 mint for the first bridge + 1 for the second (each holds its own client).
	if *tokenCalls != 2 {
		t.Errorf("token calls = %d, want 2 (one per client, cached within)", *tokenCalls)
	}
}
