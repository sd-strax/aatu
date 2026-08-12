package substrate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/gowebpki/jcs"
)

// ContentHash is a hex SHA-256 over canonical content bytes (§3). Computed
// exclusively by the store; consumers verify, never compute.
type ContentHash string

// HashVersionV1 is the §3 scheme: SHA-256 over the UTF-8 bytes of the
// RFC 8785 (JCS) canonical JSON of the content object
//
//	{ "advice": ..., "body": ..., "meta": ..., "tags": [...], "title": ... }
//
// with tags sorted lexicographically and deduplicated, and absent optional
// fields omitted entirely (never null). The hash covers content only — not
// status, revision, principals, provenance, or timestamps. The scheme is a
// one-way door: consumers record these hashes in their own immutable audit
// trails, so a future scheme is a new hash_version computed alongside, never
// a reinterpretation of v1.
const HashVersionV1 = 1

// Content is the hashed subset of an entry — the §3 content object and the
// §6 snapshot payload.
type Content struct {
	Title  string         `json:"title"`
	Body   string         `json:"body"`
	Tags   []string       `json:"tags"`
	Meta   map[string]any `json:"meta,omitempty"`
	Advice string         `json:"advice,omitempty"`
}

// canonicalTags returns tags sorted lexicographically and deduplicated,
// normalizing nil to the empty list (the "tags" key is always present).
func canonicalTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// hashContent computes the v1 content hash. The canonical form is produced by
// a real RFC 8785 implementation — meta is arbitrary JSON, and JCS number
// serialization is not something to hand-roll under a one-way door.
func hashContent(c Content) (ContentHash, error) {
	obj := map[string]any{
		"title": c.Title,
		"body":  c.Body,
		"tags":  canonicalTags(c.Tags),
	}
	// Absent optional fields are omitted entirely, never null (§3).
	if c.Meta != nil {
		obj["meta"] = c.Meta
	}
	if c.Advice != "" {
		obj["advice"] = c.Advice
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("substrate: marshal content: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("substrate: canonicalize content (RFC 8785): %w", err)
	}
	sum := sha256.Sum256(canonical)
	return ContentHash(hex.EncodeToString(sum[:])), nil
}
