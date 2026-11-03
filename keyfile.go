package innerva

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// LoadOrCreateProofKey loads a durable P-256 key or creates it with owner-only permissions.
func LoadOrCreateProofKey(path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("proof key path is required")
	}
	key, err := loadProofKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create proof key directory: %w", err)
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate proof key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal proof key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return loadProofKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create proof key file: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write proof key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync proof key: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("close proof key: %w", err)
	}
	return key, nil
}

func loadProofKey(path string) (*ecdsa.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&0o077 != 0 {
		return nil, errors.New("proof key file must be regular and accessible only by its owner")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read proof key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("proof key file is not one EC private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil || key.Curve != elliptic.P256() {
		return nil, errors.New("proof key file must contain a P-256 key")
	}
	return key, nil
}
