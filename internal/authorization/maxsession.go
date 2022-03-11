package authorization

import (
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/mohammed90/caddy-ssh/internal/session"
	"github.com/mohammed90/caddy-ssh/internal/ssh"
	"go.uber.org/zap"
)

type MaxSession struct {
	MaxSessions uint64 `json:"max_sessions,omitempty"`

	mu                  *sync.Mutex
	currentSessionCount uint64

	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (ms *MaxSession) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.session.authorize.max_session",
		New: func() caddy.Module {
			return new(MaxSession)
		},
	}
}

func (ms *MaxSession) Provision(ctx caddy.Context) error {
	ms.logger = ctx.Logger(ms)
	ms.mu = &sync.Mutex{}
	return nil
}

func (ms *MaxSession) Authorize(sess session.Session) (DeauthorizeFunc, bool, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if (ms.currentSessionCount + 1) > ms.MaxSessions {
		ms.logger.Info("session count exceeds max",
			zap.Uint64("max_session_count", ms.MaxSessions),
			zap.Uint64("current_session_count", ms.currentSessionCount),
			zap.String("user", sess.User()),
			zap.String("remote_ip", sess.RemoteAddr().String()),
			zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
		)
		return nil, false, nil
	}
	ms.logger.Info("session authorized",
		zap.String("user", sess.User()),
		zap.String("remote_ip", sess.RemoteAddr().String()),
		zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
		zap.Uint64("active_session_count", ms.increment()),
	)
	return ms.deauthorize, true, nil
}

func (ms *MaxSession) deauthorize(sess session.Session) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.logger.Info("session deauthorized",
		zap.String("user", sess.User()),
		zap.String("remote_ip", sess.RemoteAddr().String()),
		zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
		zap.Uint64("active_session_count", ms.decrement()),
	)
	return nil
}

func (ss *MaxSession) increment() uint64 {
	return atomic.AddUint64(&ss.currentSessionCount, 1)
}
func (ss *MaxSession) decrement() uint64 {
	return atomic.AddUint64(&ss.currentSessionCount, ^uint64(0))
}

var _ caddy.Module = (*MaxSession)(nil)
var _ caddy.Provisioner = (*MaxSession)(nil)
var _ Authorizer = (*MaxSession)(nil)
