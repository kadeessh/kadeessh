package authentication

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

var (
	_ caddy.Provisioner = (*PublicKeyFlow)(nil)
)

func init() {
	caddy.RegisterModule(PublicKeyFlow{})
}

// PublicKeyFlow holds the public key authentication providers
type PublicKeyFlow struct {
	authenticatorLogger
	// A set of authentication providers implementing the UserPublicKeyAuthenticator interface. If none are specified,
	// all requests will always be unauthenticated.
	ProvidersRaw caddy.ModuleMap                       `json:"providers,omitempty" caddy:"namespace=ssh.authentication.providers.public_key"`
	providers    map[string]UserPublicKeyAuthenticator `json:"-"`

	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (PublicKeyFlow) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.flows.public_key",
		New: func() caddy.Module { return new(PublicKeyFlow) },
	}
}

// Provision sets up and loads the providers of conforming to UserPublicKeyAuthenticator interface
func (pk *PublicKeyFlow) Provision(ctx caddy.Context) error {
	pk.logger = ctx.Logger(pk)
	pk.authenticatorLogger = authenticatorLogger{pk.logger}

	pk.providers = make(map[string]UserPublicKeyAuthenticator)
	mods, err := ctx.LoadModule(pk, "ProvidersRaw")
	if err != nil {
		return fmt.Errorf("loading authentication providers: %v", err)
	}

	for modName, modIface := range mods.(map[string]interface{}) {
		if pka, ok := modIface.(UserPublicKeyAuthenticator); ok {
			pk.providers[modName] = pka
			continue
		}
		return fmt.Errorf("%+v is not type UserPublicKeyAuthenticator", modIface)
	}
	return nil
}

func (pk PublicKeyFlow) callback(ctx session.Context) func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
	return func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		pk.authStart(conn, len(pk.providers), ctx.RemoteAddr(), zap.String("key_type", key.Type()))
		for name, auther := range pk.providers { //nolint:golint,misspell
			user, authed, err := auther.AuthenticateUser(conn, key)
			if err != nil {
				pk.authError(conn, name, err, zap.String("key_type", key.Type()))
				continue
			}
			if !authed {
				pk.authFailed(conn, name, zap.String("key_type", key.Type()))
				continue
			}
			pk.authSuccessful(conn, name, user, zap.String("key_type", key.Type()))
			ctx.SetValue(UserCtxKey, user)
			return user.Permissions(), nil
		}
		pk.invalidCredentials(conn, zap.String("key_type", key.Type()))
		return nil, invalidCredentials
	}
}
