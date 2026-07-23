package clientcreds

import (
	"testing"

	"github.com/zalando/go-keyring"
)

// TestAnthropicKey_RoundTrip exercises set/get/delete against the in-memory
// mock provider (keyring.MockInit) so the test never touches the real OS
// keychain.
func TestAnthropicKey_RoundTrip(t *testing.T) {
	keyring.MockInit()

	// Absent: found=false, no error.
	if v, found, err := GetAnthropicKey(); err != nil || found || v != "" {
		t.Fatalf("absent key = %q,%v,%v; want \"\",false,nil", v, found, err)
	}

	if err := SetAnthropicKey("sk-ant-roundtrip"); err != nil {
		t.Fatalf("SetAnthropicKey: %v", err)
	}
	v, found, err := GetAnthropicKey()
	if err != nil || !found || v != "sk-ant-roundtrip" {
		t.Fatalf("GetAnthropicKey = %q,%v,%v; want the stored key", v, found, err)
	}

	if err := DeleteAnthropicKey(); err != nil {
		t.Fatalf("DeleteAnthropicKey: %v", err)
	}
	if _, found, _ := GetAnthropicKey(); found {
		t.Error("key still present after delete")
	}
	// Deleting an absent key is a no-op, not an error.
	if err := DeleteAnthropicKey(); err != nil {
		t.Errorf("delete of absent key returned %v; want nil", err)
	}
}
