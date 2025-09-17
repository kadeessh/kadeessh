package pty

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/ssh"
	"go.uber.org/zap"
)

var _ PtyAsker = Allow{}

func init() {
	caddy.RegisterModule(Allow{})
}

// Allow is PtyAsker module which always allows the PTY session
type Allow struct {
	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (Allow) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.ask.pty.allow",
		New: func() caddy.Module {
			return new(Allow)
		},
	}
}

// Provision sets up the Allow module
func (e *Allow) Provision(ctx caddy.Context) error {
	e.logger = ctx.Logger(e)
	return nil
}

// Allow always returns true
func (e Allow) Allow(ctx ssh.Context, pty ssh.Pty) bool {
	e.logger.Info(
		"asking for permission",
		zap.String("session_id", ctx.SessionID()),
		zap.String("local_address", ctx.LocalAddr().String()),
		zap.String("client_version", ctx.ClientVersion()),
		zap.String("user", ctx.User()),
		zap.String("terminal", pty.Term),
	)
	return true
}
