package authorization

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/mohammed90/caddy-ssh/internal/session"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(Chained))
}

type Chained struct {
	AuthorizersRaw []json.RawMessage `json:"authorize,omitempty" caddy:"namespace=ssh.session.authorize inline_key=authorizer"`

	authorizers []Authorizer

	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (c *Chained) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.session.authorize.chained",
		New: func() caddy.Module {
			return new(Chained)
		},
	}
}

func (c *Chained) Provision(ctx caddy.Context) error {
	c.logger = ctx.Logger(c)

	authzIface, err := ctx.LoadModule(c, "AuthorizersRaw")
	if err != nil {
		return fmt.Errorf("loading authorizer modules: %v", err)
	}
	for _, authorizer := range authzIface.([]interface{}) {
		c.authorizers = append(c.authorizers, authorizer.(Authorizer))
	}
	return nil
}

func (c *Chained) Authorize(sess session.Session) (DeauthorizeFunc, bool, error) {

	deauthors := []DeauthorizeFunc{}
	authed := true

	for i := 0; authed && i < len(c.authorizers); i++ {
		deauth, a := c.authorizers[i].Authorize(sess)
		authed = authed && a

		// prepend
		deauthors = append([]DeauthorizeFunc{deauth}, deauthors...)
	}
	if !authed {
		var err error
		for _, deauther := range deauthors {
			if perr := deauther(sess); perr != nil {
				err = multierr.Append(err, perr)
			}
		}
		return nil, authed, err
	}

	return func(s session.Session) error {
		var err error
		for _, deauther := range deauthors {
			if perr := deauther(s); perr != nil {
				err = multierr.Append(err, perr)
			}
		}
		return err
	}, true, nil
}

var _ caddy.Provisioner = (*Chained)(nil)
var _ Authorizer = (*Chained)(nil)
