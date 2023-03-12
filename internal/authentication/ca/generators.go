package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
)

type privateKey []byte

func (p privateKey) PrivateBytes() []byte {
	return []byte(p)
}

type publicKey []byte

func (p publicKey) PublicBytes() []byte {
	return []byte(p)
}

func pemEncode(private privateKey, public publicKey, typ string) (privateKey, publicKey) {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  strings.TrimSpace(strings.Join([]string{typ, "PRIVATE", "KEY"}, " ")),
			Bytes: private.PrivateBytes(),
		},
	), public.PublicBytes()
}

func generateRSA(bits int) (privateKey, publicKey) {
	// impossible to err given the code in rsa.GenerateMultiPrimeKey
	pkey, _ := rsa.GenerateKey(rand.Reader, bits)
	privKey, _ := x509.MarshalPKCS8PrivateKey(pkey)
	pubKey, _ := x509.MarshalPKIXPublicKey(&pkey.PublicKey)
	return pemEncode((privKey), (pubKey), "RSA")
}

func generateEd25519() (privateKey, publicKey) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	return privateKey(privKey), publicKey(pubKey)
}
