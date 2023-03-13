package signer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/caddyserver/caddy/v2"
	internalcaddyssh "github.com/kadeessh/kadeessh/internal"
	"github.com/kadeessh/kadeessh/internal/session"
	gossh "golang.org/x/crypto/ssh"
)

var _ internalcaddyssh.SignerConfigurator = (*File)(nil)

func init() {
	caddy.RegisterModule(File{})
}

// File is a session signer that uses pre-existing keys, which may be backed
// as files
type File struct {
	// The file system implementation to use. The default is the local disk file system.
	// File system modules used here must implement the fs.FS interface
	FileSystemRaw json.RawMessage `json:"file_system,omitempty" caddy:"namespace=caddy.fs inline_key=backend"`
	fileSystem    fs.FS

	// The collection of `signer.Key` resources.
	// Relative paths are appended to the path of the current working directory.
	// The supported PEM types and algorithms are:
	// - RSA PRIVATE KEY: RSA
	// - PRIVATE KEY: RSA, ECDSA, ed25519
	// - EC PRIVATE KEY: ECDSA
	// - DSA PRIVATE KEY: DSA
	// - OPENSSH PRIVATE KEY: RSA, ed25519, ECDSA
	Keys    []Key `json:"keys,omitempty"`
	signers []gossh.Signer
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (s File) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.signers.file",
		New: func() caddy.Module {
			return new(File)
		},
	}
}

// Provision loads the keys from the specified URLs
func (s *File) Provision(ctx caddy.Context) error {
	if len(s.Keys) == 0 {
		return errors.New("path for host key file missing")
	}
	if len(s.FileSystemRaw) > 0 {
		mod, err := ctx.LoadModule(s, "FileSystemRaw")
		if err != nil {
			return fmt.Errorf("loading file system module: %v", err)
		}
		s.fileSystem = mod.(fs.FS)
	}
	if s.fileSystem == nil {
		s.fileSystem = osReadFS{}
	}

	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
		ctx.Context = context.WithValue(ctx.Context, caddy.ReplacerCtxKey, repl)
	}

	for i, v := range s.Keys {
		keyPath := repl.ReplaceKnown(v.Source, "")
		if !filepath.IsAbs(keyPath) {
			var err error
			keyPath, err := filepath.Abs(keyPath)
			if err != nil {
				return fmt.Errorf("error absoluting key at index %d with file path '%s': %s", i, keyPath, err)
			}
		}
		passphrase := repl.ReplaceKnown(v.Passphrase, "")
		f, err := s.fileSystem.Open(keyPath)
		if err != nil {
			return fmt.Errorf("error opening key at index %d with file name '%s': %s", i, keyPath, err)
		}

		keysBytes, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("error reading key at index %d with file name '%s': %s", i, keyPath, err)
		}

		signer, err := parseSigner(keysBytes, passphrase)
		if err != nil {
			return fmt.Errorf("error parsing the private key: %s", err)
		}
		s.signers = append(s.signers, signer)
	}
	return nil
}

// Configure adds the signers/hostkeys to the session
func (f *File) Configure(ctx session.Context, cfg internalcaddyssh.SignerAdder) {
	for _, v := range f.signers {
		cfg.AddHostKey(v)
	}
}

type osReadFS struct{}

func (osReadFS) Open(name string) (fs.File, error) { return os.Open(name) }
