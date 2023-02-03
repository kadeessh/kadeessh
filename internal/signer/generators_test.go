package signer

import (
	"crypto"
	"os"
	"testing"

	"github.com/pkg/errors"
	"go.step.sm/crypto/pemutil"
	gossh "golang.org/x/crypto/ssh"
)

func TestRoundTrip(t *testing.T) {
	type wants struct {
		priv privateKey
		typ  string
	}
	tests := []struct {
		name    string
		wants   wants
		wantErr bool
	}{
		{
			name: "RSA Signer",
			wants: wants{
				priv: generateRSA(),
				typ:  "ssh-rsa",
			},
			wantErr: false,
		},
		{
			name: "Ed25519 Signer",
			wants: wants{
				priv: generateEd25519(),
				typ:  "ssh-ed25519",
			},
			wantErr: false,
		},
		{
			name: "RSA from file",
			wants: wants{
				priv: func() privateKey {
					f, _ := os.ReadFile("./testdata/ssh_host_rsa_key")
					k, err := pemutil.ParseOpenSSHPrivateKey(f)
					if err != nil {
						t.Errorf("failed to parse RSA key: %s", err)
						t.FailNow()
					}
					return k.(privateKey)
				}(),
				typ: "ssh-rsa",
			},
			wantErr: false,
		},
		{
			name: "Ed25519 from file",
			wants: wants{
				priv: func() privateKey {
					f, _ := os.ReadFile("./testdata/ssh_host_ed25519_key")
					// pemutil.ParseOpenSSHPrivateKey(f)
					k, err := pemutil.ParseOpenSSHPrivateKey(f)
					if err != nil {
						t.Errorf("failed to parse ed25519 key: %s", err)
						t.FailNow()
					}
					return k.(privateKey)
				}(),
				typ: "ssh-ed25519",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubbytes, err := encodePublicKey(tt.wants.priv.Public())
			if err != nil {
				t.Errorf("error encodePublicKey: %s", err)
				return
			}

			privbytes, err := pemEncode(tt.wants.priv)
			if err != nil {
				t.Errorf("error pemEncode: %s", err)
				return
			}

			signer, public, err := decode(pemBytes(privbytes), pubbytes)
			if err != nil {
				t.Errorf("error decoding: %s", err)
				return
			}
			if signer == nil || public == nil {
				t.Errorf("signer: %T, public key: %T", signer, tt.wants.priv.Public())
				return
			}
			if signer.PublicKey().Type() != tt.wants.typ {
				t.Errorf("decode() type = %s, want = %s", signer.PublicKey().Type(), tt.wants.typ)
			}
		})
	}
}

func decode(priv, pub []byte) (gossh.Signer, crypto.PublicKey, error) {
	// gossh.PublicKey, comment string, options []string, rest []byte, err error
	pubkey, _, _, _, err := gossh.ParseAuthorizedKey(pub)
	if err != nil {
		return nil, nil, errors.Wrap(err, "ParseAuthorizedKey")
	}
	signer, err := gossh.ParsePrivateKey(priv)
	if err != nil {
		return nil, nil, errors.Wrap(err, "ParsePrivateKey")
	}
	return signer, pubkey, err
}
