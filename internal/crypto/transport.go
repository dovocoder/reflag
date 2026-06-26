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
)

// DeriveTransportKey derives an AES-256 key from a partial API key.
// Uses the first 16 characters of the API key (after the rfk_ prefix)
// as the key material, hashed with SHA-256.
// Both client and server derive the same key independently.
func DeriveTransportKey(rawAPIKey string) []byte {
	// Use the first 16 chars of the raw key (after prefix) as key material
	// This ensures a partial key compromise doesn't reveal the full API key
	keyMaterial := rawAPIKey
	if len(keyMaterial) > 20 {
		// Use chars 4-20 (skip "rfk_", take next 16 chars)
		keyMaterial = keyMaterial[4:20]
	}
	hash := sha256.Sum256([]byte("reflag-transport:" + keyMaterial))
	return hash[:]
}

// EncryptPayload encrypts a JSON payload using AES-256-GCM with a key derived
// from the API key. Returns a base64-encoded nonce+ciphertext.
func EncryptPayload(plaintext []byte, transportKey []byte) (string, error) {
	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	combined := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

// DecryptPayload decrypts a base64-encoded nonce+ciphertext using AES-256-GCM.
func DecryptPayload(encoded string, transportKey []byte) ([]byte, error) {
	combined, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(combined) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := combined[:nonceSize]
	ciphertext := combined[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
