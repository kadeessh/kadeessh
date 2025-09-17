package authorization

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
)

func init() {
	caddy.RegisterModule(new(MaxSession))
}

type DeauthorizeFunc func(session.Session) error

// Authorizer interface is the basis for authorizers in the namespace ssh.session.authorizers. An erroed
// authorization should not require a call to DeauthorizeFunc.
type Authorizer interface {
	Authorize(session.Session) (DeauthorizeFunc, bool, error)
}
