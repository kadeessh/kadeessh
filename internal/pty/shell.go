package pty

import (
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/pty/passwd"
	"github.com/kadeessh/kadeessh/internal/session"
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

// Shell is an `ssh.actors` module providing "shell" to a session. The module spawns a process
// using the user's default shell, as defined in the OS. On *nix, except for macOS, the module parses `/etc/passwd`,
// for the details and caches the result for future logins. On macOS, the module calls `dscl . -read` for the necessary
// user details and caches them for future logins. On Windows, the module uses the
// [`os/user` package](https://pkg.go.dev/os/user?GOOS=windows) from the Go standard library.
type Shell struct {
	// Executes the designated command using the user's default shell, regardless of
	// the supplied command. It follows the OpenSSH semantics specified for
	// the [`ForceCommand`](https://man.openbsd.org/OpenBSD-current/man5/sshd_config.5#ForceCommand) except for
	// the part about `internal-sftp`.
	ForceCommand string `json:"force_command"`

	// environment variables to be set for the session
	Env map[string]string `json:"env,omitempty"`

	// whether the server should check for explicit pty request
	ForcePTY bool `json:"force_pty,omitempty"`

	logger *zap.Logger
	pass   passwd.Passwd
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
	s.pass = passwd.New()
	return nil
}

// Handle opens a PTY to run the command
func (s Shell) Handle(sess session.Session) error {
	spty, err := s.openPty(sess)
	if err != nil {
		s.logger.Error("error opening pty", zap.Error(err))
		sess.Close()
		return err
	}
	spty.Communicate(sess)
	return spty.Close()
}

var _ session.Handler = Shell{}
