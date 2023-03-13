package authorization

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
)

func init() {
	caddy.RegisterModule(new(Public))
}

// Public authorizes all sessions
type Public struct{}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (ms *Public) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.session.authorizers.public",
		New: func() caddy.Module {
			return new(Public)
		},
	}
}

// Provision is an noop for this module
func (ms *Public) Provision(ctx caddy.Context) error {
	return nil
}

// Authorize is an noop for this module
func (ms *Public) Authorize(sess session.Session) (DeauthorizeFunc, bool, error) {
	return ms.deauthorize, true, nil
}

func (ms *Public) deauthorize(session.Session) error {
	return nil
}

var _ caddy.Module = (*Public)(nil)
var _ caddy.Provisioner = (*Public)(nil)
var _ Authorizer = (*Public)(nil)
