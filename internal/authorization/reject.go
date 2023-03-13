package authorization

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
)

func init() {
	caddy.RegisterModule(new(Reject))
}

// Reject rejects all sessions
type Reject struct{}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (ms *Reject) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.session.authorizers.reject",
		New: func() caddy.Module {
			return new(Public)
		},
	}
}

// Provision is an noop for this module
func (ms *Reject) Provision(ctx caddy.Context) error {
	return nil
}

// Authorize is an noop for this module, except for returning false to deny the session.
func (ms *Reject) Authorize(sess session.Session) (DeauthorizeFunc, bool, error) {
	return ms.deauthorize, false, nil
}

func (ms *Reject) deauthorize(session.Session) error {
	return nil
}

var _ caddy.Module = (*Reject)(nil)
var _ caddy.Provisioner = (*Reject)(nil)
var _ Authorizer = (*Reject)(nil)
