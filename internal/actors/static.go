package actors

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
)

func init() {
	caddy.RegisterModule(StaticResponse{})
}

// StaticResponse is an actor that writes a static value to the client
type StaticResponse struct {
	Response string `json:"response"`
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (s StaticResponse) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.actors.static_response",
		New: func() caddy.Module {
			return new(StaticResponse)
		},
	}
}

// Provision is a noop for this module
func (s *StaticResponse) Provision(ctx caddy.Context) error {
	return nil
}

// Handle will write the value of Response to the client
func (s StaticResponse) Handle(sess session.Session) error {
	_, err := fmt.Fprintln(sess, s.Response)
	return err
}
