package signer

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	internalcaddyssh "github.com/mohammed90/caddy-ssh/internal"
	"github.com/mohammed90/caddy-ssh/internal/session"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

var _ internalcaddyssh.SignerConfigurator = (*Fallback)(nil)

func init() {
	caddy.RegisterModule(Fallback{})
}

// Fallback will check if the signers exist in the storage, otherwise generate them. It is
// the default signer.
type Fallback struct {
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
	if exists := f.storage.Exists(filepath.Join("ssh", "signer", "ssh_host_rsa_key")); !exists {
		private, public := generateRSA(4096)
		signersBytes = append(signersBytes, private.PrivateBytes())
		if err := f.storage.Store(filepath.Join("ssh", "signer", "ssh_host_rsa_key"), private.PrivateBytes()); err != nil {
			return err
		}
		if err := f.storage.Store(filepath.Join("ssh", "signer", "ssh_host_rsa_key.pub"), public.PublicBytes()); err != nil {
			return err
		}
	} else {
		bs, err := f.storage.Load(filepath.Join("ssh", "signer", "ssh_host_rsa_key"))
		if err != nil {
			return err
		}
		signersBytes = append(signersBytes, bs)
	}

	// ed25519
	if exists := f.storage.Exists(filepath.Join("ssh", "signer", "ssh_host_ed25519_key")); !exists {
		private, public := generateEd25519()

		if err := f.storage.Store(filepath.Join("ssh", "signer", "ssh_host_ed25519_key"), private.PrivateBytes()); err != nil {
			return err
		}
		if err := f.storage.Store(filepath.Join("ssh", "signer", "ssh_host_ed25519_key.pub"), public.PublicBytes()); err != nil {
			return err
		}
		signersBytes = append(signersBytes, private.PrivateBytes())
	} else {
		bs, err := f.storage.Load(filepath.Join("ssh", "signer", "ssh_host_ed25519_key"))
		if err != nil {
			return err
		}
		signersBytes = append(signersBytes, bs)
	}

	// ecdsa &  DSA intentionally not generated, but existing keys are loaded
	if f.storage.Exists(filepath.Join("ssh", "signer", "ssh_host_ecdsa_key")) {
		bs, err := f.storage.Load(filepath.Join("ssh", "signer", "ssh_host_ecdsa_key"))
		if err != nil {
			return err
		}
		signersBytes = append(signersBytes, bs)
	}
	if f.storage.Exists(filepath.Join("ssh", "signer", "ssh_host_dsa_key")) {
		bs, err := f.storage.Load(filepath.Join("ssh", "signer", "ssh_host_dsa_key"))
		if err != nil {
			return err
		}
		signersBytes = append(signersBytes, bs)
	}

	// load signers
	for _, sb := range signersBytes {
		s, err := gossh.ParsePrivateKey(sb)
		if err != nil {
			return err
		}
		f.signers = append(f.signers, s)
	}

	return nil
}

func (f *Fallback) GoSSHSigner() []gossh.Signer {
	keys, err := f.storage.List(filepath.Join("ssh", "signer"), true)
	if err != nil {
		// they were provisioned milliseconds ago, listing them shouldn't fail.
		panic(err)
	}
	signers := make([]gossh.Signer, 0)
	for _, v := range keys {
		// we don't parse public keys as signers
		if strings.ToLower(filepath.Ext(v)) == ".pub" {
			continue
		}
		bs, err := f.storage.Load(v)
		if err != nil {
			panic(err)
		}
		s, err := gossh.ParsePrivateKey(bs)
		if err != nil {
			panic(err)
		}
		signers = append(signers, s)
	}
	return signers
}

func (f *Fallback) Configure(ctx session.Context, cfg internalcaddyssh.SignerAdder) {
	for _, v := range f.signers {
		cfg.AddHostKey(v)
	}
}
