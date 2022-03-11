package authorization

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/mohammed90/caddy-ssh/internal/session"
)

func init() {
	caddy.RegisterModule(new(Public))
}

type Public struct{}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (ms *Public) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: NamespacePrefix + ".public",
		New: func() caddy.Module {
			return new(Public)
		},
	}
}

func (ms *Public) Provision(ctx caddy.Context) error {
	return nil
}

func (ms *Public) Authorize(sess session.Session) (DeauthorizeFunc, bool, error) {
	return ms.deauthorize, true, nil
}

func (ms *Public) deauthorize(session.Session) error {
	return nil
}

var _ caddy.Module = (*Public)(nil)
var _ caddy.Provisioner = (*Public)(nil)
var _ Authorizer = (*Public)(nil)
