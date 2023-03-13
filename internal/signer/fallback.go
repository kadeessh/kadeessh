package signer

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	internalcaddyssh "github.com/kadeessh/kadeessh/internal"
	"github.com/kadeessh/kadeessh/internal/session"
	"go.step.sm/crypto/pemutil"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

var _ internalcaddyssh.SignerConfigurator = (*Fallback)(nil)

const (
	rsa_host_key     = "ssh_host_rsa_key"
	ed25519_host_key = "ssh_host_ed25519_key"
	ecdsa_host_key   = "ssh_host_ecdsa_key"
)

func init() {
	caddy.RegisterModule(Fallback{})
}

// Fallback signer checks if the RSA, Ed25519, and ECDSA private keys exist in the storage to load. If they're absent,
// RSA-4096 and Ed25519 keys are generated and stored. The ECDSA key is only loaded, not generated.
// It is the default signer.
type Fallback struct {
	// The Caddy storage module to load/store the keys. If absent or null, the default storage is loaded.
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`
	signers    []gossh.Signer
	storage    certmagic.Storage
	logger     *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (f Fallback) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.signers.fallback",
		New: func() caddy.Module {
			return new(Fallback)
		},
	}
}

// Provision sets up the Fallback module by loading the storage module then generating/loading the keys as necessary
func (f *Fallback) Provision(ctx caddy.Context) error {
	f.logger = ctx.Logger(f)
	if f.StorageRaw != nil {
		val, err := ctx.LoadModule(f, "StorageRaw")
		if err != nil {
			return fmt.Errorf("loading storage module: %v", err)
		}
		st, err := val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return fmt.Errorf("creating storage configuration: %v", err)
		}
		f.storage = st
	}
	if f.storage == nil {
		f.storage = ctx.Storage()
	}
	f.signers = []gossh.Signer{}
	signersBytes := [][]byte{}

	// RSA
	if err := loadOrGenerateAndStore(ctx, f.storage, rsa_host_key, generateRSA, &signersBytes); err != nil {
		return err
	}

	// ed25519
	if err := loadOrGenerateAndStore(ctx, f.storage, ed25519_host_key, generateEd25519, &signersBytes); err != nil {
		return err
	}

	// ECDSA is only loaded, not generated
	if err := loadFromStorage(ctx, f.storage, ecdsa_host_key, &signersBytes); f.storage.Exists(ctx, filepath.Join(keyPath(ecdsa_host_key)...)) && err != nil {
		return err
	}

	// DSA is intentionally ignored

	// load signers
	for _, sb := range signersBytes {
		s, err := pemutil.ParseOpenSSHPrivateKey(sb)
		if err != nil {
			return err
		}
		sig, err := gossh.NewSignerFromKey(s)
		if err != nil {
			return err
		}
		f.signers = append(f.signers, sig)
	}

	return nil
}

func loadOrGenerateAndStore(ctx context.Context, storage certmagic.Storage, keyName string, generator func() privateKey, signersBytes *[][]byte) error {
	if !storage.Exists(ctx, filepath.Join(keyPath(keyName)...)) {
		// prepare the keys bytes
		private := generator()
		keyPem, err := pemEncode(private)
		if err != nil {
			return err
		}
		public, err := encodePublicKey(private.Public())
		if err != nil {
			return err
		}

		// write 'em
		if err := storage.Store(ctx, filepath.Join(keyPath(keyName)...), pemBytes(keyPem)); err != nil {
			return err
		}
		if err := storage.Store(ctx, filepath.Join(keyPath(keyName+".pub")...), public); err != nil {
			return err
		}
		*signersBytes = append(*signersBytes, pemBytes(keyPem))
		return nil
	}
	return loadFromStorage(ctx, storage, keyName, signersBytes)
}

func loadFromStorage(ctx context.Context, storage certmagic.Storage, keyName string, signersBytes *[][]byte) error {
	bs, err := storage.Load(ctx, filepath.Join(keyPath(keyName)...))
	if err != nil {
		return err
	}
	*signersBytes = append(*signersBytes, bs)
	return nil
}

// Configure adds the signers/hostkeys to the session
func (f *Fallback) Configure(ctx session.Context, cfg internalcaddyssh.SignerAdder) {
	for _, v := range f.signers {
		cfg.AddHostKey(v)
	}
}
