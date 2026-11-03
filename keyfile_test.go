package innerva

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateProofKeyPersistsWithOwnerOnlyPermissions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keys", "proof.pem")
	first, err := LoadOrCreateProofKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateProofKey(path)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, firstErr := x509.MarshalECPrivateKey(first)
	secondBytes, secondErr := x509.MarshalECPrivateKey(second)
	if firstErr != nil || secondErr != nil || !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("reopened key differs from the created key")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions = %o", info.Mode().Perm())
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateProofKey(path); err == nil {
		t.Fatal("accepted a group/world-readable key")
	}
}
