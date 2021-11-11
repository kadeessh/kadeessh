//go:build (darwin || linux || freebsd || netbsd) && cgo && pam
// +build darwin linux freebsd netbsd
// +build cgo
// +build pam

package osauth

import (
	"errors"
	"os/user"

	"github.com/caddyserver/caddy/v2"
	"github.com/mohammed90/caddy-ssh/internal/authentication"
	"github.com/mohammed90/caddy-ssh/internal/session"
	"github.com/msteinert/pam"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(OS{})
}

type OS struct {
	logger *zap.Logger
}

func (OS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.providers.password.os",
		New: func() caddy.Module { return new(OS) },
	}
}

func (pm *OS) Provision(ctx caddy.Context) error {
	pm.logger = ctx.Logger(pm)
	return nil
}

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
