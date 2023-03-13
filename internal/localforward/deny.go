package localforward

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/ssh"
	"go.uber.org/zap"
)

var _ PortForwardingAsker = Deny{}

func init() {
	caddy.RegisterModule(Deny{})
}

// Allow is PortForwardingAsker module which always rejects the session
type Deny struct {
	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (Deny) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.ask.localforward.deny",
		New: func() caddy.Module {
			return new(Deny)
		},
	}
}

// Provision sets up the Deny module
func (e *Deny) Provision(ctx caddy.Context) error {
	e.logger = ctx.Logger(e)
	return nil
}

// Allow always returns false to deny the local forward session
func (e Deny) Allow(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
	e.logger.Info(
		"asking for permission",
		zap.String("session_id", ctx.SessionID()),
		zap.String("local_address", ctx.LocalAddr().String()),
		zap.String("remote_address", ctx.RemoteAddr().String()),
		zap.String("client_version", ctx.ClientVersion()),
		zap.String("user", ctx.User()),
		zap.String("destination_host", destinationHost),
		zap.Uint32("destination_port", destinationPort),
	)
	return false
}
