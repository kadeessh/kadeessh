//go:build (darwin || linux || freebsd || netbsd) && cgo && pam

package osauth

import (
	"errors"

	user "github.com/tweekmonster/luser"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/authentication"
	"github.com/kadeessh/kadeessh/internal/session"
	"github.com/msteinert/pam"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(OS{})
}

// OS module authenticates the user against the users of the underlying operating system using PAM
type OS struct {
	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (OS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.providers.password.os",
		New: func() caddy.Module { return new(OS) },
	}
}

// Provision sets up the module
func (pm *OS) Provision(ctx caddy.Context) error {
	pm.logger = ctx.Logger(pm)
	return nil
}

// AuthenticateUser uses PAM to authenticate users
func (pm OS) AuthenticateUser(sshctx session.ConnMetadata, password []byte) (authentication.User, bool, error) {
	pm.logger.Info("auth begin", zap.String("username", sshctx.User()))

	// "sshd" is the OS service
	t, err := pam.StartFunc("sshd", sshctx.User(), func(s pam.Style, _ string) (string, error) {
		switch s {
		case pam.PromptEchoOff:
			return string(password), nil
		default:
			return "", errors.New("unsupported message style")
		}
	})
	if err != nil {
		pm.logger.Warn("error StartFunc", zap.Error(err))
		return nil, false, err
	}
	err = t.Authenticate(0)
	if err != nil {
		pm.logger.Warn("error Authenticate", zap.Error(err))
		return nil, false, err
	}
	err = t.AcctMgmt(0)
	if err != nil {
		pm.logger.Warn("error Pam AcctMgmt", zap.Error(err))
		return nil, false, err
	}
	u, err := user.Lookup(sshctx.User())
	if err != nil {
		return nil, false, err
	}

	a := account{
		user: u,
	}
	return a, true, nil
}

var _ authentication.UserPasswordAuthenticator = (*OS)(nil)
