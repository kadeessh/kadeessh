package mfa

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

// SealedBox is a base64 nacl/secretbox payload with a 24-byte prefixed
// nonce. Format: base64(nonce || box). Zero-value SealedBox is empty.
type SealedBox string

// Seal encrypts plaintext using key. A fresh 24-byte random nonce is
// generated per call and prefixed to the ciphertext.
func Seal(key [32]byte, plaintext []byte) (SealedBox, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("mfa: generating nonce: %w", err)
	}
	out := make([]byte, 24, 24+len(plaintext)+secretbox.Overhead)
	copy(out, nonce[:])
	out = secretbox.Seal(out, plaintext, &nonce, &key)
	return SealedBox(base64.StdEncoding.EncodeToString(out)), nil
}

// Open decrypts a SealedBox previously produced by Seal with the same
// key. Returns an error if the payload is malformed or the
// authentication tag fails to verify.
func (s SealedBox) Open(key [32]byte) ([]byte, error) {
	if s == "" {
		return nil, errors.New("mfa: sealed box is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(string(s))
	if err != nil {
		return nil, fmt.Errorf("mfa: decoding sealed box: %w", err)
	}
	if len(raw) < 24+secretbox.Overhead {
		return nil, errors.New("mfa: sealed box truncated")
	}
	var nonce [24]byte
	copy(nonce[:], raw[:24])
	plain, ok := secretbox.Open(nil, raw[24:], &nonce, &key)
	if !ok {
		// Deliberately terse: never leak whether decryption vs. auth
		// failed, and never include the ciphertext in the error.
		return nil, errors.New("mfa: sealed box authentication failed")
	}
	return plain, nil
}
