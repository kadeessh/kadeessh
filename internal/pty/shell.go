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

// Shell is an `ssh.actors` module providing "shell" to a session.
type Shell struct {
	// the shell designated for the session
	Shell string `json:"shell"`

	// environment variables to be set for the session
	Env map[string]string `json:"env,omitempty"`

	// whether the server should check for explicit pty request
	ForcePTY bool `json:"force_pty,omitempty"`
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

// Provision sets up the Shell module
func (s *Shell) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger(s)
	return nil
}

// Handle opens a PTY to run the command
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
