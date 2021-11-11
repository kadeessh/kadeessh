package pty

import (
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/mohammed90/caddy-ssh/internal/session"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Shell{})
}

type sshPty interface {
	Communicate(io.ReadWriter)
	SetWindowsSize(w, h int)
	Close() error
}

type Shell struct {
	Shell    string            `json:"shell"`
	Env      map[string]string `json:"env,omitempty"`
	ForcePTY bool              `json:"force_pty,omitempty"`
	logger   *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (s Shell) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.actors.shell",
		New: func() caddy.Module {
			return new(Shell)
		},
	}
}

func (s *Shell) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger(s)
	return nil
}

func (s Shell) Handle(sess session.Session) error {
	spty, err := s.openPty(sess, sess.Command())
	if err != nil {
		s.logger.Error("error opening pty", zap.Error(err))
		sess.Close()
		return err
	}
	spty.Communicate(sess)
	return nil
}

var _ session.Handler = Shell{}
