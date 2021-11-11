package internalcaddyssh

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mohammed90/caddy-ssh/internal/localforward"
	caddypty "github.com/mohammed90/caddy-ssh/internal/pty"
	"github.com/mohammed90/caddy-ssh/internal/reverseforward"
	"github.com/mohammed90/caddy-ssh/internal/ssh"
	"github.com/mohammed90/caddy-ssh/internal/subsystem"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

func init() {
	caddy.RegisterModule(SSH{})
}

type caddySshServerCtxKey string

const CtxServerName caddySshServerCtxKey = "CtxServerName"

// SSH provides Public Key Infrastructure facilities for Caddy.
type SSH struct {
	GracePeriod   caddy.Duration     `json:"grace_period,omitempty"`
	Servers       map[string]*Server `json:"servers,omitempty"`
	servers       []*ssh.Server
	serverIndexer map[string][]int // maps server name to the indices in the `servers` field
	errGroup      *errgroup.Group
	ctx           caddy.Context
	log           *zap.Logger
}

type Server struct {
	Address string `json:"address,omitempty"`

	LocalForwardRaw json.RawMessage                  `json:"localforward,omitempty" caddy:"namespace=ssh.ask.localforward inline_key=forward"`
	localForward    localforward.PortForwardingAsker `json:"-"`

	ReverseForwardRaw json.RawMessage                    `json:"reverseforward,omitempty" caddy:"namespace=ssh.ask.reverseforward inline_key=forward"`
	reverseForward    reverseforward.PortForwardingAsker `json:"-"`

	PtyAskRaw json.RawMessage   `json:"pty,omitempty" caddy:"namespace=ssh.ask.pty inline_key=pty"`
	ptyAsk    caddypty.PtyAsker `json:"-"`

	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`
	MaxTimeout  caddy.Duration `json:"max_timeout,omitempty"`

	SubsystemRaw caddy.ModuleMap              `json:"subsystems,omitempty" caddy:"namespace=ssh.subsystem"`
	subsystems   map[string]subsystem.Handler `json:"-"`

	Config ConfigList `json:"configs,omitempty"`

	Actors ActorList `json:"actors,omitempty"`

	name        string
	listenRange caddy.NetworkAddress
	logger      *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (SSH) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh",
		New: func() caddy.Module { return new(SSH) },
	}
}

// Provision sets up the configuration for the SSH app.
func (app *SSH) Provision(ctx caddy.Context) error {
	app.ctx = ctx
	app.log = ctx.Logger(app)
	app.serverIndexer = make(map[string][]int)
	for srvName, srv := range app.Servers {
		add, err := caddy.ParseNetworkAddress(srv.Address)
		if err != nil {
			return err
		}
		if add.Network != "tcp" {
			return fmt.Errorf("only 'tcp' is supported in the listener address")
		}
		ctx.Context = context.WithValue(ctx, CtxServerName, srvName)
		srv.name = srvName
		srv.logger = app.log.Named(srvName)
		srv.listenRange = add

		{
			// default to disable for strict reasons
			if srv.LocalForwardRaw == nil || len(srv.LocalForwardRaw) == 0 {
				srv.LocalForwardRaw = json.RawMessage(
					[]byte(`{"forward": "deny" }`),
				)
			}
			mods, err := ctx.LoadModule(srv, "LocalForwardRaw")
			if err != nil {
				return fmt.Errorf("loading localforward callback: %v", err)
			}
			lforwarder, ok := mods.(localforward.PortForwardingAsker)
			if !ok {
				return fmt.Errorf("loading localforward callback: specified callback is not localforward.PortForwardingCallback")
			}
			srv.localForward = lforwarder
		}

		{
			// default to disable for strict reasons
			if srv.ReverseForwardRaw == nil || len(srv.ReverseForwardRaw) == 0 {
				srv.ReverseForwardRaw = json.RawMessage(
					[]byte(`{"forward": "deny" }`),
				)
			}
			mods, err := ctx.LoadModule(srv, "ReverseForwardRaw")
			if err != nil {
				return fmt.Errorf("loading reverseforward callback: %v", err)
			}
			rforwarder, ok := mods.(reverseforward.PortForwardingAsker)
			if !ok {
				return fmt.Errorf("loading reverseforward callback: specified callback is not reverseforward.PortForwardingCallback")
			}
			srv.reverseForward = rforwarder
		}
		{
			// default to disable for strict reasons
			if srv.PtyAskRaw == nil || len(srv.PtyAskRaw) == 0 {
				srv.PtyAskRaw = json.RawMessage(
					[]byte(`{"pty": "deny" }`),
				)
			}
			mods, err := ctx.LoadModule(srv, "PtyAskRaw")
			if err != nil {
				return fmt.Errorf("loading pty callback: %v", err)
			}
			ptyasker, ok := mods.(caddypty.PtyAsker)
			if !ok {
				return fmt.Errorf("loading pty callback: specified callback is not pty.PtyAsker")
			}
			srv.ptyAsk = ptyasker
		}
		if srv.SubsystemRaw != nil || len(srv.SubsystemRaw) == 0 {
			srv.subsystems = make(map[string]subsystem.Handler)
			mods, err := ctx.LoadModule(srv, "SubsystemRaw")
			if err != nil {
				return fmt.Errorf("loading subsystem providers: %v", err)
			}
			for modName, modIface := range mods.(map[string]interface{}) {
				srv.subsystems[modName] = modIface.(subsystem.Handler)
			}
		}

		if err := srv.Config.Provision(ctx); err != nil {
			return err
		}

		if err := srv.Actors.Provision(ctx); err != nil {
			return err
		}

		for portOffset := uint(0); portOffset < srv.listenRange.PortRangeSize(); portOffset++ {
			sshsrv := &ssh.Server{
				Addr:                          srv.listenRange.JoinHostPort(portOffset),
				IdleTimeout:                   time.Duration(srv.IdleTimeout),
				MaxTimeout:                    time.Duration(srv.MaxTimeout),
				LocalPortForwardingCallback:   srv.localForward.Allow,
				ReversePortForwardingCallback: srv.reverseForward.Allow,
				PtyCallback:                   srv.ptyAsk.Allow,
				ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig {
					for _, cfger := range srv.Config {
						if cfger.MatcherSets.AnyMatch(ctx) {
							return cfger.Configurator.ServerConfigCallback(ctx)
						}
					}
					return &gossh.ServerConfig{}
				},
			}
			if srv.localForward != nil || srv.reverseForward != nil {
				forwardHandler := &ssh.ForwardedTCPHandler{}
				if sshsrv.RequestHandlers == nil {
					sshsrv.RequestHandlers = make(map[string]ssh.RequestHandler)
				}
				if sshsrv.ChannelHandlers == nil {
					sshsrv.ChannelHandlers = make(map[string]ssh.ChannelHandler)
					// re-plug the default session handler
					sshsrv.ChannelHandlers["session"] = ssh.DefaultSessionHandler
				}
				sshsrv.RequestHandlers["tcpip-forward"] = forwardHandler.HandleSSHRequest
				sshsrv.RequestHandlers["cancel-tcpip-forward"] = forwardHandler.HandleSSHRequest
				sshsrv.ChannelHandlers["direct-tcpip"] = ssh.DirectTCPIPHandler
			}

			if len(srv.subsystems) > 0 {
				sshsrv.SubsystemHandlers = make(map[string]ssh.SubsystemHandler)
			}
			for ss, hndler := range srv.subsystems {
				sshsrv.SubsystemHandlers[ss] = func(s ssh.Session) {
					hndler.Handle(s)
				}
			}

			sshsrv.Handle(func(sess ssh.Session) {
				srv.logger.Info("session started",
					zap.String("user", sess.User()),
					zap.String("remote_ip", sess.RemoteAddr().String()),
					zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
				)

				defer srv.logger.Info("session ended",
					zap.String("user", sess.User()),
					zap.String("remote_ip", sess.RemoteAddr().String()),
					zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
				)

				var errs []error
				for _, actor := range srv.Actors {
					if actor.matcherSets.AnyMatch(sess) {
						err := actor.handler.Handle(sess)
						if err != nil {
							errs = append(errs, err)
						}
						if actor.Final {
							break
						}
					}
				}

				exitCode := 0
				if len(errs) != 0 {
					exitCode = 1
					srv.logger.Error("actors errors", zap.Errors("errors", errs))
				}
				if err := sess.Exit(exitCode); err != nil {
					srv.logger.Error("error on exit",
						zap.Error(err),
						zap.String("remote_ip", sess.RemoteAddr().String()),
						zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)))
					return
				}
			})
			app.serverIndexer[srvName] = append(app.serverIndexer[srvName], len(app.servers))
			app.servers = append(app.servers, sshsrv)
		}
	}
	return nil
}

// Start starts the SSH app.
func (app *SSH) Start() error {
	app.errGroup = &errgroup.Group{}
	for _, srv := range app.servers {
		ln, err := caddy.Listen("tcp", srv.Addr)
		if err != nil {
			return fmt.Errorf("ssh: listening on %s: %v", srv.Addr, err)
		}
		srv := srv
		app.errGroup.Go(func() error {
			return srv.Serve(ln)
		})
	}
	return nil
}

// Stop stops the SSH app.
func (app *SSH) Stop() error {
	ctx := context.Background()
	if app.GracePeriod > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(app.GracePeriod))
		defer cancel()
	}
	for _, s := range app.servers {
		err := s.Shutdown(ctx)
		if err != nil {
			return err
		}
	}
	return app.errGroup.Wait()
}

// Interface guards
var (
	_ caddy.Provisioner = (*SSH)(nil)
	_ caddy.App         = (*SSH)(nil)
)
