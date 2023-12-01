package osauth

import (
	"os"
	"path/filepath"

	user "github.com/tweekmonster/luser"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/authentication"
	"github.com/kadeessh/kadeessh/internal/session"
	"github.com/kadeessh/kadeessh/internal/ssh"
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

// PublicKey is an authenticator that authenticates the user based on the `.ssh/authorized_keys` in
// the user's $HOME
type PublicKey struct {
	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (PublicKey) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.providers.public_key.os",
		New: func() caddy.Module { return new(PublicKey) },
	}
}

// Provision sets up the PublicKey authentication module
func (o *PublicKey) Provision(ctx caddy.Context) error {
	o.logger = ctx.Logger(o)
	return nil
}

// AuthenticateUser loads the $HOME`/.ssh/authorized_keys` of the user to look for a matching key. The user is denied
// if none of the list of keys in `authorized_keys` match the submitted keys.
func (o *PublicKey) AuthenticateUser(ctx session.ConnMetadata, pubkey gossh.PublicKey) (authentication.User, bool, error) {
	username := ctx.User()
	o.logger.Debug(
		"authenticating user",
		zap.String("username", username),
		zap.String("submitted_key_type", pubkey.Type()),
	)
	u, err := user.Lookup(username)
	if err != nil {
		return account{}, false, err
	}
	authKeysFiles := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	o.logger.Debug(
		"assumed path to authorized keys",
		zap.String("user_homedir", u.HomeDir),
		zap.String("path", authKeysFiles),
	)
	if _, err := os.Stat(authKeysFiles); err != nil && os.IsNotExist(err) {
		return account{}, false, nil
	} else if err != nil {
		return account{}, false, err
	}
	authKeysBytes, err := os.ReadFile(authKeysFiles)
	if err != nil {
		return account{}, false, err
	}
	o.logger.Debug(
		"loaded authorized keys",
		zap.String("path", authKeysFiles),
		zap.Int("size", len(authKeysBytes)),
	)
	keysCount := 0
	for len(authKeysBytes) > 0 {
		key, comment, options, rest, err := ssh.ParseAuthorizedKey(authKeysBytes)
		if err != nil {
			return account{}, false, err
		}
		keysCount++
		o.logger.Debug(
			"parsed an authorized key",
			zap.String("key_type", key.Type()),
			zap.String("comment", comment),
			zap.Strings("options", options),
		)
		if ssh.KeysEqual(key, pubkey) {
			o.logger.Debug(
				"authorized key matched",
				zap.String("key_type", key.Type()),
			)
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
	o.logger.Debug("loaded authorized keys", zap.Int("count", keysCount))
	return account{}, false, nil // TODO: report an error?
}
