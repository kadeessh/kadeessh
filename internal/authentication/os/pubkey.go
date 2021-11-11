package osauth

import (
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/caddyserver/caddy/v2"
	"github.com/mohammed90/caddy-ssh/internal/authentication"
	"github.com/mohammed90/caddy-ssh/internal/session"
	"github.com/mohammed90/caddy-ssh/internal/ssh"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

var (
	_ authentication.UserPublicKeyAuthenticator = (*PublicKey)(nil)
	_ caddy.Provisioner                         = (*PublicKey)(nil)
)

func init() {
	caddy.RegisterModule(PublicKey{})
}

type PublicKey struct {
	logger *zap.Logger
}

func (PublicKey) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.providers.public_key.os",
		New: func() caddy.Module { return new(PublicKey) },
	}
}

func (o *PublicKey) Provision(ctx caddy.Context) error {
	o.logger = ctx.Logger(o)
	return nil
}

func (o *PublicKey) AuthenticateUser(ctx session.ConnMetadata, pubkey gossh.PublicKey) (authentication.User, bool, error) {
	username := ctx.User()
	u, err := user.Lookup(username)
	if err != nil {
		return account{}, false, err
	}
	o.logger.Debug("authenticating user", zap.String("username", username))
	authKeysFiles := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	if _, err := os.Stat(authKeysFiles); err != nil && os.IsNotExist(err) {
		return account{}, false, nil
	}
	authKeysBytes, err := ioutil.ReadFile(authKeysFiles)
	if err != nil {
		return account{}, false, err
	}
	for len(authKeysBytes) > 0 {
		key, _, _, rest, err := ssh.ParseAuthorizedKey(authKeysBytes)
		if err != nil {
			return account{}, false, err
		}
		if ssh.KeysEqual(key, pubkey) {
			return account{
				user: u,
				permissions: &gossh.Permissions{
					CriticalOptions: map[string]string{
						"user": username,
					},
					Extensions: map[string]string{
						// Record the public key used for authentication
						"pubkey-fp": gossh.FingerprintSHA256(pubkey),
						"pubkey":    string(pubkey.Marshal()),
					},
				},
			}, true, nil
		}
		authKeysBytes = rest
	}
	return account{}, false, nil // TODO: report an error?
}
