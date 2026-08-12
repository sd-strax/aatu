package substrate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestOpenAICompatEmbedder exercises the wire shape against a fake endpoint:
// auth header, request body, out-of-order response indexes.
func TestOpenAICompatEmbedder(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/embeddings" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk-test" {
			t.Errorf("auth = %q", got)
		}
		var req embedRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Model != "test-model" || len(req.Input) != 2 {
			t.Errorf("req = %+v", req)
		}
		// Deliberately out of order: the client must reorder by index.
		_, _ = w.Write([]byte(`{"data":[
			{"index":1,"embedding":[0.5,0.5]},
			{"index":0,"embedding":[1.0,0.0]}
		]}`))
	}))
	defer srv.Close()

	e, err := NewOpenAICompatEmbedder(srv.URL+"/v1/", "sk-test", "test-model", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	vecs, err := e.Embed(context.Background(), []string{"first", "second"})
	if err != nil {
		t.Fatal(err)
	}
	if vecs[0][0] != 1.0 || vecs[1][0] != 0.5 {
		t.Fatalf("vectors not reordered by index: %v", vecs)
	}
}

func TestOpenAICompatEmbedderNoKeyNoHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			t.Error("Authorization header sent with empty key")
		}
		_, _ = w.Write([]byte(`{"data":[{"index":0,"embedding":[0.1]}]}`))
	}))
	defer srv.Close()
	e, err := NewOpenAICompatEmbedder(srv.URL, "", "local-model", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Embed(context.Background(), []string{"x"}); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAICompatEmbedderErrors(t *testing.T) {
	t.Run("http error carries a body snippet", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":{"message":"invalid model"}}`, http.StatusBadRequest)
		}))
		defer srv.Close()
		e, _ := NewOpenAICompatEmbedder(srv.URL, "k", "m", srv.Client())
		_, err := e.Embed(context.Background(), []string{"x"})
		if err == nil || !strings.Contains(err.Error(), "HTTP 400") || !strings.Contains(err.Error(), "invalid model") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("count mismatch is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"data":[{"index":0,"embedding":[0.1]}]}`))
		}))
		defer srv.Close()
		e, _ := NewOpenAICompatEmbedder(srv.URL, "k", "m", srv.Client())
		if _, err := e.Embed(context.Background(), []string{"a", "b"}); err == nil {
			t.Fatal("want error on 1 vector for 2 inputs")
		}
	})
	t.Run("config is validated", func(t *testing.T) {
		if _, err := NewOpenAICompatEmbedder("", "k", "m", nil); err == nil {
			t.Fatal("want error on empty base_url")
		}
		if _, err := NewOpenAICompatEmbedder("http://x", "k", "", nil); err == nil {
			t.Fatal("want error on empty model")
		}
	})
}
