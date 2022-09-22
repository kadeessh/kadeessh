package signer

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/caddyserver/caddy/v2"
	internalcaddyssh "github.com/mohammed90/caddy-ssh/internal"
	"github.com/mohammed90/caddy-ssh/internal/session"
	gossh "golang.org/x/crypto/ssh"
)

var _ internalcaddyssh.SignerConfigurator = (*Static)(nil)

func init() {
	caddy.RegisterModule(Static{})
}

// Keyfile is a holder of the path and passphrase of key files.
type Keyfile struct {
	// Path should be an acceptable URL, so for on-disk files
	// it should be `file:///path/to/file/on/disk`
	Path       string `json:"path,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// Static is a session signer that uses pre-existing keys, which may be backed
// as files or retrievable via HTTP
type Static struct {
	Keys    []Keyfile `json:"keys,omitempty"`
	signers []gossh.Signer
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (s Static) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.signers.file",
		New: func() caddy.Module {
			return new(Static)
		},
	}
}

// Provision loads the keys from the specified URLs
func (s *Static) Provision(ctx caddy.Context) error {
	if len(s.Keys) == 0 {
		return errors.New("path for host key file missing")
	}
	repl := caddy.NewReplacer()

	t := &http.Transport{}
	// The path is set by the server administrator, not by arbitrary user.
	// nolint:gosec
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	c := &http.Client{Transport: t}

	for _, v := range s.Keys {

		keyPath, err := url.Parse(repl.ReplaceKnown(v.Path, ""))
		if err != nil {
			return err
		}
		passphrase := repl.ReplaceKnown(v.Passphrase, "")

		var keysBytes []byte
		switch keyPath.Scheme {
		case "http", "https", "file":
			res, err := c.Get(keyPath.String())
			if err != nil {
				return err
			}
			keysBytes, err = ioutil.ReadAll(res.Body)
			if err != nil {
				res.Body.Close()
				return err
			}
			res.Body.Close()
		default:
			return fmt.Errorf("unsupported key source: %s", keyPath.Scheme)
		}

		var signer gossh.Signer
		if v.Passphrase != "" {
			signer, err = gossh.ParsePrivateKeyWithPassphrase(keysBytes, []byte(passphrase))
		} else {
			signer, err = gossh.ParsePrivateKey(keysBytes)
		}
		if err != nil {
			return fmt.Errorf("error parsing the private key: %s", err)
		}
		s.signers = append(s.signers, signer)
	}
	return nil
}

// Configure adds the signers/hostkeys to the session
func (f *Static) Configure(ctx session.Context, cfg internalcaddyssh.SignerAdder) {
	for _, v := range f.signers {
		cfg.AddHostKey(v)
	}
}
