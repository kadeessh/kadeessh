package internalcaddyssh

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/authorization"
	"github.com/kadeessh/kadeessh/internal/localforward"
	caddypty "github.com/kadeessh/kadeessh/internal/pty"
	"github.com/kadeessh/kadeessh/internal/reverseforward"
	"github.com/kadeessh/kadeessh/internal/ssh"
	"github.com/kadeessh/kadeessh/internal/subsystem"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

func init() {
	caddy.RegisterModule(SSH{})
}

type caddySshServerCtxKey string

const CtxServerName caddySshServerCtxKey = "CtxServerName"

// SSH is the app providing ssh services
type SSH struct {
	// GracePeriod is the duration a server should wait for open connections to close during shutdown
	// before closing them forcefully
	GracePeriod caddy.Duration `json:"grace_period,omitempty"`

	// The set of ssh servers keyed by custom names
	Servers       map[string]*Server `json:"servers,omitempty"`
	servers       []*sshServer
	serverIndexer map[string][]int // maps server name to the indices in the `servers` field
	errGroup      *errgroup.Group
	ctx           caddy.Context
	log           *zap.Logger
}

type sshServer struct {
	*ssh.Server
}

type Server struct {
	// Socket addresses to which to bind listeners. Accepts
	// [network addresses](/docs/conventions#network-addresses)
	// that may include port ranges. Listener addresses must
	// be unique; they cannot be repeated across all defined
	// servers. TCP is the only acceptable network (for now, perhaps).
	Address string `json:"address,omitempty"`

	// The configuration of local-forward permission module. The config structure is:
	// "localforward": {
	// 		"forward": "<module name>"
	// 		... config
	// }
	// defaults to: { "forward": "deny" }
	LocalForwardRaw json.RawMessage                  `json:"localforward,omitempty" caddy:"namespace=ssh.ask.localforward inline_key=forward"`
	localForward    localforward.PortForwardingAsker `json:"-"`

	// The configuration of reverse-forward permission module. The config structure is:
	// "reverseforward": {
	// 		"forward": "<module name>"
	// 		... config
	// }
	// defaults to: { "reverseforward": "deny" }
	ReverseForwardRaw json.RawMessage                    `json:"reverseforward,omitempty" caddy:"namespace=ssh.ask.reverseforward inline_key=forward"`
	reverseForward    reverseforward.PortForwardingAsker `json:"-"`

	// The configuration of PTY permission module. The config structure is:
	// "pty": {
	// 		"pty": "<module name>"
	// 		... config
	// }
	// defaults to: { "forward": "deny" }
	PtyAskRaw json.RawMessage   `json:"pty,omitempty" caddy:"namespace=ssh.ask.pty inline_key=pty"`
	ptyAsk    caddypty.PtyAsker `json:"-"`

	// connection timeout when no activity, none if empty
	IdleTimeout caddy.Duration `json:"idle_timeout,omitempty"`
	// absolute connection timeout, none if empty
	MaxTimeout caddy.Duration `json:"max_timeout,omitempty"`

	// The configuration of the authorizer module. The config structure is:
	// "authorize": {
	// 		"authorizer": "<module name>"
	// 		... config
	// }
	// default to: { "authorizer": "public" }.
	AuthorizeRaw json.RawMessage `json:"authorize,omitempty" caddy:"namespace=ssh.session.authorizers inline_key=authorizer"`
	authorizer   authorization.Authorizer

	// The list of defined subsystems in a json structure keyed by the arbitrary name of the subsystem.
	// TODO: The current implementation is naive and can be expanded to follow the Authorzation and Actors model
	SubsystemRaw caddy.ModuleMap              `json:"subsystems,omitempty" caddy:"namespace=ssh.subsystem"`
	subsystems   map[string]subsystem.Handler `json:"-"`

	// List of configurators that could configure the server per matchers and config providers
	Config ConfigList `json:"configs,omitempty"`

	// The actors that can act on a session per the matching criteria
	Actors ActorList `json:"actors,omitempty"`

	name        string
	listenRange caddy.NetworkAddress
	logger      *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
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
			if srv.AuthorizeRaw == nil || len(srv.AuthorizeRaw) == 0 {
				srv.AuthorizeRaw = json.RawMessage(
					[]byte(`{"authorizer": "public" }`),
				)
			}
			mods, err := ctx.LoadModule(srv, "AuthorizeRaw")
			if err != nil {
				return fmt.Errorf("loading authorizer callback: %v", err)
			}
			authorizer, ok := mods.(authorization.Authorizer)
			if !ok {
				return fmt.Errorf("loading authorizer callback: specified callback is not authorization.Authorizer")
			}
			srv.authorizer = authorizer
		}
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
			sshsrv := &sshServer{
				Server: &ssh.Server{
					// used in this manner to preserve the *relative* NetworkAddress
					Addr:                          caddy.JoinNetworkAddress(add.Network, add.Host, strconv.Itoa(int(srv.listenRange.StartPort+portOffset))),
					IdleTimeout:                   time.Duration(srv.IdleTimeout),
					MaxTimeout:                    time.Duration(srv.MaxTimeout),
					LocalPortForwardingCallback:   srv.localForward.Allow,
					ReversePortForwardingCallback: srv.reverseForward.Allow,
					PtyCallback:                   srv.ptyAsk.Allow,
					ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig {
						for _, cfger := range srv.Config {
							if cfger.matcherSets.AnyMatch(ctx) {
								return cfger.configurator.ServerConfigCallback(ctx)
							}
						}
						return &gossh.ServerConfig{}
					},
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
				var deauth authorization.DeauthorizeFunc
				var ok bool
				if deauth, ok, err = srv.authorizer.Authorize(sess); !ok && err == nil {
					srv.logger.Info("session not authorized",
						zap.String("user", sess.User()),
						zap.String("remote_ip", sess.RemoteAddr().String()),
						zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
					)
					return
				} else if err != nil {
					srv.logger.Error("error on session authorization",
						zap.String("user", sess.User()),
						zap.String("remote_ip", sess.RemoteAddr().String()),
						zap.String("session_id", sess.Context().Value(ssh.ContextKeySessionID).(string)),
						zap.Error(err),
					)
					return
				}
				// TODO: error checking
				defer deauth(sess) // nolint

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
		netadd, _ := caddy.ParseNetworkAddress(srv.Addr)
		ln, err := caddy.Listen("tcp", netadd.JoinHostPort(0))
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
