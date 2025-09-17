package static

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/authentication"
	"github.com/kadeessh/kadeessh/internal/session"
	"github.com/kadeessh/kadeessh/internal/ssh"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	caddy.RegisterModule(StaticPublicKeyProvider{})
}

var (
	_ authentication.UserPublicKeyAuthenticator = (*StaticPublicKeyProvider)(nil)
	_ caddy.Provisioner                         = (*StaticPublicKeyProvider)(nil)
)

type User struct {
	// the login username identifying the user
	Username string `json:"username"`
	// url to the location, e.g. file:///path/to/file or https://github.com/username.keys
	Keys []string `json:"keys,omitempty"`

	sshKeys []ssh.PublicKey
}

type StaticPublicKeyProvider struct {
	// the user list along ith their keys sources
	Users    []User          `json:"users,omitempty"`
	userList map[string]User `json:"-"`
	logger   *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (StaticPublicKeyProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.providers.public_key.static",
		New: func() caddy.Module { return new(StaticPublicKeyProvider) },
	}
}

// Provision loads up the users' keys from the named sources, which may be https? or file.
// TODO: modularize the source to allow arbitrary sources, e.g. Hashicorp Vault
func (pk *StaticPublicKeyProvider) Provision(ctx caddy.Context) error {
	pk.userList = make(map[string]User)
	pk.logger = ctx.Logger(pk)
	repl := caddy.NewReplacer()

	t := &http.Transport{}
	// The path is set by the server administrator, not by arbitrary user.
	// nolint:gosec
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	c := &http.Client{Transport: t}

	for _, user := range pk.Users {
		for _, kurl := range user.Keys {
			u, err := url.Parse(repl.ReplaceKnown(kurl, ""))
			if err != nil {
				return err
			}
			var authKeysBytes []byte
			switch u.Scheme {
			case "http", "https", "file":
				res, err := c.Get(u.String())
				if err != nil {
					return err
				}
				authKeysBytes, err = io.ReadAll(res.Body)
				if err != nil {
					res.Body.Close()
					return err
				}
				res.Body.Close()
			default:
				return fmt.Errorf("unsupported key source: %s", u.Scheme)
			}

			keys := []ssh.PublicKey{}
			for len(authKeysBytes) > 0 {
				k, _, _, rest, err := ssh.ParseAuthorizedKey(authKeysBytes)
				if err != nil {
					return err
				}
				keys = append(keys, k)
				authKeysBytes = rest
			}
			user.sshKeys = append(user.sshKeys, keys...)
		}
		pk.userList[user.Username] = user
	}
	return nil
}

// AuthenticateUser looks up the use in the in-memory map and grab the key to match against the presented key. It adds the key fingerprint
// in the extensions of the permissions, keyed with "pubkey-fp".
func (pk StaticPublicKeyProvider) AuthenticateUser(ctx session.ConnMetadata, pubkey gossh.PublicKey) (authentication.User, bool, error) {
	username := ctx.User()
	if username == "" {
		return Account{}, false, nil
	}

	acc, ok := pk.userList[username]
	if !ok {
		return Account{}, false, nil // TODO: should report an error?
	}

	for _, key := range acc.sshKeys {
		if ssh.KeysEqual(key, pubkey) {
			return Account{
				ID:    acc.Username,
				Uname: acc.Username,
				permissions: &gossh.Permissions{
					CriticalOptions: map[string]string{
						"user": username,
					},
					Extensions: map[string]string{
						// Record the public key used for authentication
						"pubkey-fp": gossh.FingerprintSHA256(pubkey),
					},
				},
			}, true, nil
		}
	}
	return Account{}, false, nil
}
