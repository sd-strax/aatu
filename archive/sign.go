package archive

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// Ed25519Signer signs bundle content hashes with an ed25519 key (07 §2.2). The
// signature is detached and verifiable independently of reckon — a third party
// needs only the public key and the content hash.
type Ed25519Signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

// KeyID is a stable id for the signing key — the hex SHA-256 of the public key,
// truncated. It lets the chain record WHICH key signed without embedding the
// public key in every bundle.
func (s *Ed25519Signer) KeyID() string { return s.keyID }

// Alg names the signature algorithm.
func (*Ed25519Signer) Alg() string { return "ed25519" }

// Sign returns the detached signature over the given digest (the SHA-256 of
// the manifest bytes).
func (s *Ed25519Signer) Sign(digest []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, digest), nil
}

// PublicKey returns the verifying key, so callers can persist/publish it for
// independent verification.
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// NewEd25519Signer wraps an existing private key.
func NewEd25519Signer(priv ed25519.PrivateKey) *Ed25519Signer {
	return &Ed25519Signer{priv: priv, keyID: keyID(priv.Public().(ed25519.PublicKey))}
}

// GenerateEd25519Signer mints a fresh key. Used by tests and by first-run key
// creation.
func GenerateEd25519Signer() (*Ed25519Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return NewEd25519Signer(priv), nil
}

// LoadOrCreateSigner loads the tenant signing key from path, minting and
// persisting one on first use (07 §2.2: "generated and stored in OS keychain
// for solo" — v0 uses a 0600 file under the data dir; keychain integration is a
// v1 refinement). The private key is written 0600; the public key alongside it
// as <path>.pub for independent verification.
func LoadOrCreateSigner(path string) (*Ed25519Signer, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(raw) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("signing key at %s is malformed (%d bytes)", path, len(raw))
		}
		return NewEd25519Signer(ed25519.PrivateKey(raw)), nil
	case os.IsNotExist(err):
		s, gerr := GenerateEd25519Signer()
		if gerr != nil {
			return nil, gerr
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create key dir: %w", err)
		}
		if err := os.WriteFile(path, s.priv, 0o600); err != nil {
			return nil, fmt.Errorf("write signing key: %w", err)
		}
		if err := os.WriteFile(path+".pub", s.PublicKey(), 0o644); err != nil {
			return nil, fmt.Errorf("write public key: %w", err)
		}
		return s, nil
	default:
		return nil, fmt.Errorf("read signing key %s: %w", path, err)
	}
}

func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}
