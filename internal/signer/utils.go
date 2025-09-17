package signer

import (
	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ssh"
)

// Key is a generic holder of the location and passphrase of key (abstract) files
type Key struct {
	// Source is the identifying path of the key depending on the source. In the case of `file` signer,
	// `Source` refers to the path to the file on disk in relative or absolute path forms. Other signers
	// are free to define the semantics of the field.
	Source string `json:"source,omitempty"`

	// A non-empty value means the key is protected with a passphrase
	Passphrase string `json:"passphrase,omitempty"`
}

func parseSigner(key []byte, passphrase string) (ssh.Signer, error) {
	opts := []pemutil.Options{}
	if passphrase != "" {
		opts = append(opts, pemutil.WithPassword([]byte(passphrase)))
	}
	privKey, err := pemutil.ParseOpenSSHPrivateKey(key, opts...)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(privKey)
}

func keyPath(keyName string) []string {
	return []string{"ssh", "signer", keyName}
}
