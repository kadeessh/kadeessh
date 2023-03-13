package subsystem

import (
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
	"github.com/pkg/sftp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(InMemSFTP{})
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (s InMemSFTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.subsystem.inmem_sftp",
		New: func() caddy.Module {
			return new(InMemSFTP)
		},
	}
}

// InMemSFTP is an in-memory SFTP server allowing shared space
// between all users. It starts with an empty space.
// Warning: For illustration purposes only!
type InMemSFTP struct {
	logger *zap.Logger
	root   sftp.Handlers
}

// Provision sets up the in-memory SFTP module
func (s *InMemSFTP) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger(s)
	s.root = sftp.InMemHandler()
	return nil
}

// Handle runs an SFTP request server for the session
func (s InMemSFTP) Handle(sess session.Session) {
	s.logger.Info("handling sftp session", zap.String("user", sess.User()), zap.String("remote_addr", sess.RemoteAddr().String()))
	server := sftp.NewRequestServer(sess, s.root)
	if err := server.Serve(); err == io.EOF {
		server.Close()
		s.logger.Info("sftp client exited session")
	} else if err != nil {
		s.logger.Error("sftp server completed with error", zap.Error(err))
	}
}

// Handler is the designated interface which subsystems should implement
type Handler interface {
	Handle(session.Session)
}
