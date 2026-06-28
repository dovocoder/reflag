package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Encrypt encrypts plaintext using AES-256-GCM with the given key.
// The key must be exactly 32 bytes. Returns nonce+ciphertext as base64.
func Encrypt(plaintext string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded AES-256-GCM ciphertext.
func Decrypt(encoded string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}

// DeriveKey derives a 32-byte AES-256 key from a passphrase using HKDF
// (HMAC-based Key Derivation Function, RFC 5869) with a domain separator.
func DeriveKey(passphrase string) []byte {
	return hkdfSHA256([]byte("reflag-secrets-key"), []byte(passphrase), 32)
}

// hkdfSHA256 implements HKDF with SHA-256 (RFC 5869) using the standard
// golang.org/x/crypto/hkdf package.
func hkdfSHA256(salt, ikm []byte, length int) []byte {
	reader := hkdf.New(sha256.New, ikm, salt, []byte("reflag-key-derivation"))
	okm := make([]byte, length)
	if _, err := io.ReadFull(reader, okm); err != nil {
		// HKDF expansion fails only if length exceeds the maximum allowed
		// by the hash output; for SHA-256 and 32-byte outputs this is impossible.
		panic(fmt.Sprintf("hkdf expand failed: %v", err))
	}
	return okm
}
