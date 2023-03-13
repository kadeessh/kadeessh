package signer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"

	"go.step.sm/crypto/pemutil"
	gossh "golang.org/x/crypto/ssh"
)

const (
	rsaBits = 4096
)

type privateKey interface {
	Public() crypto.PublicKey
}

func pemEncode(private crypto.PrivateKey) (*pem.Block, error) {
	return pemutil.SerializeOpenSSHPrivateKey(private, pemutil.WithComment("kadeessh"))
}
func pemBytes(p *pem.Block) []byte {
	return pem.EncodeToMemory(p)
}
func encodePublicKey(p crypto.PublicKey) ([]byte, error) {
	sp, err := gossh.NewPublicKey(p)
	if err != nil {
		return nil, err
	}
	return gossh.MarshalAuthorizedKey(sp), nil
}

func generateRSA() privateKey {
	// impossible to err given the code in rsa.GenerateMultiPrimeKey
	pkey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		panic(err)
	}
	return pkey
}

func generateEd25519() privateKey {
	_, ed25519_privkey, _ := ed25519.GenerateKey(rand.Reader)
	return ed25519_privkey
}
