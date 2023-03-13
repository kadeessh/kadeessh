package internalcaddyssh

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/authentication"
	"github.com/kadeessh/kadeessh/internal/session"
	gossh "golang.org/x/crypto/ssh"
)

func init() {
	caddy.RegisterModule(ProvidedConfig{})
}

// ServerConfigurator is implemented by config loaders which should produce ServerConfig of golang.org/x/crypto/ssh
// given a session context
type ServerConfigurator interface {
	ServerConfigCallback(session.Context) *gossh.ServerConfig
}

// SignerAdder interface is an abstraction so signer modules can configure *ServerConfig of golang.org/x/crypto/ssh
// without having to reference it directly to restrict their manipulation to adding hostkeys
type SignerAdder interface {
	AddHostKey(key gossh.Signer)
}

// SignerConfigurator is the target interface abstraction for signers that load and add keys
// to a session based on the session context
type SignerConfigurator interface {
	Configure(session.Context, SignerAdder)
}

// Configurator holds the set of matchers and configurators that will apply custom server
// configurations if matched
type Configurator struct {
	// The set of matchers consulted to know whether the Actor should act on a session
	MatcherSetsRaw RawConfigMatcherSet `json:"match,omitempty" caddy:"namespace=ssh.config_matchers"`
	matcherSets    ConfigMatcherSets   `json:"-"`

	// The config provider that shall configure the server for the matched session.
	// "config": {
	// 		"loader": "<actor name>"
	// 		... config loader config
	// }
	ConfiguratorRaw json.RawMessage    `json:"config,omitempty" caddy:"namespace=ssh.config.loaders inline_key=loader"`
	configurator    ServerConfigurator `json:"-"`
}

// ConfigList is a list of server config providers that can
// custom configure the server based on the session
type ConfigList []Configurator

// Provision sets up both the matchers and configurators in the configurators.
func (cl ConfigList) Provision(ctx caddy.Context) error {
	err := cl.provisionMatchers(ctx)
	if err != nil {
		return err
	}
	return cl.provisionConfigurators(ctx)
}

// provisionMatchers sets up all the matchers by loading the
// matcher modules. Only call this method directly if you need
// to set up matchers and handlers separately without having
// to provision a second time; otherwise use Provision instead.
func (cl ConfigList) provisionMatchers(ctx caddy.Context) error {
	for i := range cl {
		// matchers
		matchersIface, err := ctx.LoadModule(&cl[i], "MatcherSetsRaw")
		if err != nil {
			return fmt.Errorf("cl %d: loading matcher modules: %v", i, err)
		}
		err = cl[i].matcherSets.FromInterface(matchersIface)
		if err != nil {
			return fmt.Errorf("cl %d: %v", i, err)
		}
	}
	return nil
}

// ProvisionHandlers sets up all the handlers by loading the
// handler modules. Only call this method directly if you need
// to set up matchers and handlers separately without having
// to provision a second time; otherwise use Provision instead.
func (cl ConfigList) provisionConfigurators(ctx caddy.Context) error {
	for i := range cl {
		clIface, err := ctx.LoadModule(&cl[i], "ConfiguratorRaw")
		if err != nil {
			return fmt.Errorf("config %d: loading configurator modules: %v", i, err)
		}
		cl[i].configurator = clIface.(ServerConfigurator)
	}
	return nil
}

// Lifted and merged from golang.org/x/crypto/ssh
// ProvidedConfig holds server specific configuration data.
type ProvidedConfig struct {
	// The session signers to be loaded. The field takes the form:
	// "signer": {
	// 		"module": "<signer module name>"
	// 		... signer module config
	// }
	// If empty, the default module is "fallback", which will load existing keys, or generates and stores them if non-existent.
	SignerRaw json.RawMessage `json:"signer,omitempty"  caddy:"namespace=ssh.signers inline_key=module"`
	signer    SignerConfigurator

	// TODO: Decide whether to expose this or not. The golang.org/x/crypto/ssh picks default based on the algo.
	// Also miconifguring this knob could result in RSA failing if below 512. Given the risk of foot-gun situation,
	// this is unexposed for now.
	//
	// golang.org/x/crypto/ssh doc:
	// The maximum number of bytes sent or received after which a
	// new key is negotiated. It must be at least 256. If
	// unspecified, a size suitable for the chosen cipher is used.
	// RekeyThreshold uint64 `json:"rekey_threshold,omitempty"`

	// The allowed key exchanges algorithms. If unspecified then a
	// default set of algorithms is used.
	// WARNING: don't set it to anyting (not even empty array) unless you know the risks!
	KeyExchanges []string `json:"key_exchanges,omitempty"`

	// The allowed cipher algorithms. If unspecified then a sensible
	// default is used.
	// WARNING: don't set it to anyting (not even empty array) unless you know the risks!
	Ciphers []string `json:"ciphers,omitempty"`

	// The allowed MAC algorithms. If unspecified then a sensible default
	// is used.
	// WARNING: don't set it to anyting (not even empty array) unless you know the risks!
	MACs []string `json:"ma_cs,omitempty"`

	// NoClientAuth is true if clients are allowed to connect without
	// authenticating.
	NoClientAuth bool `json:"no_client_auth,omitempty"`

	// MaxAuthTries specifies the maximum number of authentication attempts
	// permitted per connection. If set to a negative number, the number of
	// attempts are unlimited. If set to zero, the number of attempts are limited
	// to 6.
	MaxAuthTries int `json:"max_auth_tries,omitempty"`

	// This holds the authentication suite for the various flows
	Authentication *authentication.Config `json:"authentication,omitempty"`

	// TODO: perhaps not needed? the authentication middlewares log on their own
	// AuthLogCallback, if non-nil, is called to log all authentication
	// attempts.
	authLogCallback func(conn gossh.ConnMetadata, method string, err error)

	// ServerVersion is the version identification string to announce in
	// the public handshake.
	// If empty, a reasonable default is used.
	// Note that RFC 4253 section 4.2 requires that this string start with
	// "SSH-2.0-".
	ServerVersion string `json:"server_version,omitempty"`

	// TODO: both

	// BannerCallback, if present, is called and the return string is sent to
	// the client after key exchange completed but before authentication.
	bannerCallback func(conn gossh.ConnMetadata) string
	// GSSAPIWithMICConfig includes gssapi server and callback, which if both non-nil, is used
	// when gssapi-with-mic authentication is selected (RFC 4462 section 3).
	gSSAPIWithMICConfig *gossh.GSSAPIWithMICConfig
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (pc ProvidedConfig) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "ssh.config.loaders.provided",
		New: func() caddy.Module {
			return new(ProvidedConfig)
		},
	}
}

// Provision loads and provisions the dynamic modules of the config
func (c *ProvidedConfig) Provision(ctx caddy.Context) error {
	if err := c.Authentication.Provision(ctx); err != nil {
		return err
	}

	// default to the `fallback` module, which checks storage for the
	// keys and generates them if missing.
	if c.SignerRaw == nil || len(c.SignerRaw) == 0 {
		c.SignerRaw = json.RawMessage(`{"module": "fallback" }`)
	}
	signerIface, err := ctx.LoadModule(c, "SignerRaw")
	if err != nil {
		return fmt.Errorf("error loading signer module: %v", err)
	}

	gosshSigner, ok := signerIface.(SignerConfigurator)
	if !ok {
		return fmt.Errorf("signer is not a SignerConfigurator: %T", signerIface)
	}
	c.signer = gosshSigner

	return nil
}

// ServerConfigCallback creates and returns ServerConfig of golang.org/x/crypto/ssh. The values
// are copied from the ProvidedConfig into the ServerConfig
func (c *ProvidedConfig) ServerConfigCallback(ctx session.Context) *gossh.ServerConfig {
	cfg := &gossh.ServerConfig{
		Config: gossh.Config{
			KeyExchanges: c.KeyExchanges,
			Ciphers:      c.Ciphers,
			MACs:         c.MACs,
		},
		NoClientAuth:        c.NoClientAuth,
		MaxAuthTries:        c.MaxAuthTries,
		AuthLogCallback:     c.authLogCallback,
		ServerVersion:       c.ServerVersion,
		BannerCallback:      c.bannerCallback,
		GSSAPIWithMICConfig: c.gSSAPIWithMICConfig,
	}

	if c.Authentication != nil {
		cfg.PasswordCallback = c.Authentication.PasswordCallback(ctx)
		cfg.PublicKeyCallback = c.Authentication.PublicKeyCallback(ctx)
		cfg.KeyboardInteractiveCallback = c.Authentication.InteractiveCallback(ctx)
	}
	c.signer.Configure(ctx, cfg)

	return cfg
}

var _ ServerConfigurator = (*ProvidedConfig)(nil)
