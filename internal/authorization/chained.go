package authorization

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
	"github.com/kadeessh/kadeessh/internal/ssh"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(new(Chained))
}

type deauthor struct {
	deauthor   DeauthorizeFunc
	authorizer string
}

// Chained is a multi-authorizer module that authorizes a session against multiple authorizers
type Chained struct {
	// The list of sub-authorizers to loop through to authorize a session. If an authorizer in the chain
	// fails, all the preiovusly successful authorization will be de-authorized.
	AuthorizersRaw []json.RawMessage `json:"authorize,omitempty" caddy:"namespace=ssh.session.authorizers inline_key=authorizer"`
	authorizers    []Authorizer
	logger         *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (c *Chained) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.session.authorizers.chained",
		New: func() caddy.Module {
			return new(Chained)
		},
	}
}

// Provision loads up the sub-authorizers in the chain and provisions them as loaded
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

// Authorize loops through the sub-authorizers in sequence asking for authorization and collects
// the de-authorizers in a stack. If an authorization fails, it will de-authorize the earlier pushed
// de-authorizers, except for the failed authorizer.
func (c *Chained) Authorize(sess session.Session) (DeauthorizeFunc, bool, error) {
	deauthors := []deauthor{}
	authed := true
	var err error
	for i := 0; authed && i < len(c.authorizers); i++ {
		deauth, a, autherr := c.authorizers[i].Authorize(sess)
		authed = (authed && a) || autherr != nil
		if autherr != nil {
			c.logger.Error("error authorizing session",
				zap.String("authorizer", fmt.Sprintf("%T", c.authorizers[i])),
				zap.String("user", sess.User()),
				zap.String("remote_ip", sess.RemoteAddr().String()),
				zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
				zap.Error(autherr),
			)
			err = multierr.Append(err, nil)
			break
		}
		// prepend
		deauthors = append([]deauthor{{deauthor: deauth, authorizer: fmt.Sprintf("%T", c.authorizers[i])}}, deauthors...)
	}
	if !authed {
		for _, deauther := range deauthors {
			if perr := deauther.deauthor(sess); perr != nil {
				c.logger.Error("error deauthorizing post failed authorization",
					zap.String("authorizer", deauther.authorizer),
					zap.String("user", sess.User()),
					zap.String("remote_ip", sess.RemoteAddr().String()),
					zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
					zap.Error(perr),
				)
				err = multierr.Append(err, perr)
			}
		}
		return nil, authed, err
	}
	c.logger.Info("session authorized",
		zap.String("user", sess.User()),
		zap.String("remote_ip", sess.RemoteAddr().String()),
		zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
	)
	return func(s session.Session) error {
		var err error
		for _, deauther := range deauthors {
			if perr := deauther.deauthor(s); perr != nil {
				c.logger.Error("error deauthorizing session",
					zap.String("authorizer", deauther.authorizer),
					zap.String("user", sess.User()),
					zap.String("remote_ip", sess.RemoteAddr().String()),
					zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
					zap.Error(perr),
				)
				err = multierr.Append(err, perr)
			}
		}
		return err
	}, true, nil
}

var _ caddy.Provisioner = (*Chained)(nil)
var _ Authorizer = (*Chained)(nil)
