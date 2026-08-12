package substrate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Embedder turns texts into vectors (§10). One implementation covers the
// ecosystem: the OpenAI embeddings API shape is the de-facto wire standard,
// spoken by hosted providers (OpenAI, Voyage, Azure) and by every serious
// self-hosted stack (Ollama, vLLM, llama.cpp server) — so "which embedding
// deployment" is a base-URL config choice, not a code path. Vectors are only
// comparable within one model: the store keys every embedding row by the
// model that produced it and recall queries embed with the same model.
type Embedder interface {
	// Embed returns one vector per input text, in input order.
	Embed(ctx context.Context, texts []string) ([][]float32, error)
	// Model identifies the embedding space, e.g. "text-embedding-3-small".
	Model() string
}

// OpenAICompatEmbedder calls a POST {baseURL}/embeddings endpoint with the
// OpenAI request/response shape. The API key is a resolved literal — hosts
// resolve their secret references (keychain:// / env:// / vault://) before
// construction; the substrate never sees a reference scheme. Empty key sends
// no Authorization header (self-hosted endpoints commonly need none).
type OpenAICompatEmbedder struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

// NewOpenAICompatEmbedder builds the client. baseURL is the API prefix up to
// but excluding /embeddings (e.g. "https://api.openai.com/v1",
// "http://localhost:11434/v1"). A nil httpClient gets a 30s-timeout default.
func NewOpenAICompatEmbedder(baseURL, apiKey, model string, httpClient *http.Client) (*OpenAICompatEmbedder, error) {
	if baseURL == "" || model == "" {
		return nil, fmt.Errorf("substrate: embedder needs base_url and model")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &OpenAICompatEmbedder{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		client:  httpClient,
	}, nil
}

// Model implements Embedder.
func (e *OpenAICompatEmbedder) Model() string { return e.model }

type embedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type embedResponse struct {
	Data []struct {
		Index     int       `json:"index"`
		Embedding []float32 `json:"embedding"`
	} `json:"data"`
}

// Embed implements Embedder. Results are reordered by the response's index
// field — the shape permits out-of-order data.
func (e *OpenAICompatEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}
	body, err := json.Marshal(embedRequest{Model: e.model, Input: texts})
	if err != nil {
		return nil, fmt.Errorf("substrate: marshal embed request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("substrate: build embed request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if e.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.apiKey)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("substrate: embed call to %s: %w", e.baseURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-side close on a drained body
	if resp.StatusCode != http.StatusOK {
		// Bounded body snippet for diagnosis; never echoes the request (or key).
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("substrate: embed call to %s: HTTP %d: %s", e.baseURL, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var parsed embedResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("substrate: decode embed response: %w", err)
	}
	if len(parsed.Data) != len(texts) {
		return nil, fmt.Errorf("substrate: embed response has %d vectors for %d inputs", len(parsed.Data), len(texts))
	}
	out := make([][]float32, len(texts))
	for _, d := range parsed.Data {
		if d.Index < 0 || d.Index >= len(texts) {
			return nil, fmt.Errorf("substrate: embed response index %d out of range", d.Index)
		}
		if len(d.Embedding) == 0 {
			return nil, fmt.Errorf("substrate: embed response has an empty vector at index %d", d.Index)
		}
		out[d.Index] = d.Embedding
	}
	for i, v := range out {
		if v == nil {
			return nil, fmt.Errorf("substrate: embed response missing a vector for index %d", i)
		}
	}
	return out, nil
}
