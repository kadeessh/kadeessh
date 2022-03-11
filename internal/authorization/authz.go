package authorization

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/mohammed90/caddy-ssh/internal/session"
)

func init() {
	caddy.RegisterModule(new(MaxSession))
}

type DeauthorizeFunc func(session.Session) error

type Authorizer interface {
	Authorize(session.Session) (DeauthorizeFunc, bool, error)
}
