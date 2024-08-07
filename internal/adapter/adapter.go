package adapter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	internalcaddyssh "github.com/mohammed90/caddy-ssh/internal"
	"github.com/mohammed90/caddy-ssh/internal/authentication"
)

func init() {
	caddyconfig.RegisterAdapter("sshd_config", adapter{})
}

type adapter struct{}

type config struct {
	port                  int64
	addressFamily         string
	listenAddress         []string
	hostkey               []string
	pubkeyAuthenication   bool
	authorizedKeysFile    []string
	passworAuthentication bool
	usePam                bool
	permitRoot            bool
	agentForwarding       bool
	tcpForwarding         bool
	permitTty             bool
}

var trueRegex = regexp.MustCompile(`(?i)true|yes`)

func (a adapter) Adapt(body []byte, options map[string]interface{}) ([]byte, []caddyconfig.Warning, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(body))

	srv := &internalcaddyssh.Server{}
	con := internalcaddyssh.ProvidedConfig{
		SignerRaw:      []byte{},
		KeyExchanges:   []string{},
		Ciphers:        []string{},
		MACs:           []string{},
		NoClientAuth:   false,
		MaxAuthTries:   0,
		Authentication: nil,
		ServerVersion:  "",
	}

	conf := &config{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 0 && line[0] == '#' {
			continue // it's a comment
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 1 {
			return nil, nil, fmt.Errorf("The line contains only 1 part")
		}

		switch strings.ToLower(parts[0]) {
		case "port":
			i, err := strconv.ParseInt(parts[1], 10, 32)
			if err != nil {
				// TODO:
			}
			conf.port = i
		case "addressfamily":
		case "listenaddress":
			host, port, err := net.SplitHostPort(parts[1])
			if err != nil {
				// TODO:
			}
			srv.Address = caddy.JoinNetworkAddress("tcp", host, port)
		case "hostkey":
			ps := strings.Split(parts[1], " ")
			if conf.hostkey == nil {
				conf.hostkey = make([]string, len(ps))
			}
			conf.hostkey = append(conf.hostkey, ps...)
		case "rekeylimit":
		case "syslogfacility":
		case "loglevel":
		case "logingracetime":
		case "permitrootlogin":
			conf.permitRoot = trueRegex.MatchString(parts[1])
		case "strictmodes":
		case "maxauthtries":
			mat, err := strconv.ParseInt(parts[1], 10, 32)
			if err != nil {
				// TODO:
			}
			con.MaxAuthTries = int(mat)
		case "maxsessions":
		case "pubkeyauthentication":
			b, err := strconv.ParseBool(parts[1])
			if err != nil {
				// TODO:
			}
			if !b {
				if con.Authentication == nil {
					continue
				}
				con.Authentication.PublicKey = nil
			}
			conf.passworAuthentication = b
			if con.Authentication == nil {
				con.Authentication = &authentication.Config{}
			}
			con.Authentication.PublicKey = &authentication.PublicKeyFlow{
				ProvidersRaw: caddy.ModuleMap{
					"public_key": json.RawMessage(`{"providers": "os": {}}`),
				},
			}
		case "authorizedprincipalsfile":
		case "authorizedkeyscommand":
		case "authorizedkeyscommanduser":
		case "hostbasedauthentication":
		case "ignoreuserknownhosts":
		case "ignorerhosts":
		case "passwordauthentication":
			if !trueRegex.MatchString(parts[1]) {
				if con.Authentication == nil {
					continue
				}
				con.Authentication.UsernamePassword = nil
			}
			if con.Authentication == nil {
				con.Authentication = &authentication.Config{}
			}
			con.Authentication.UsernamePassword = &authentication.PasswordAuthFlow{
				ProvidersRaw: caddy.ModuleMap{
					"os": json.RawMessage(`{}`),
				},
			}
		case "permitemptypasswords":
			if con.Authentication != nil && con.Authentication.UsernamePassword != nil {
				con.Authentication.UsernamePassword.PermitEmptyPasswords = trueRegex.MatchString(parts[1])
			}
		case "kbdinteractiveauthentication":
		case "kerberosauthentication":
		case "kerberosorlocalpasswd":
		case "kerberosticketcleanup":
		case "kerberosgetafstoken":
		case "gssapiauthentication":
		case "gssapicleanupcredentials":
		case "usepam":
		case "allowagentforwarding":
			b, err := strconv.ParseBool(parts[1])
			if err != nil {
				// TODO:
			}
			conf.agentForwarding = b
		case "allowtcpforwarding":
			b, err := strconv.ParseBool(parts[1])
			if err != nil {
				// TODO:
			}
			conf.tcpForwarding = b
		case "gatewayports":
		case "x11forwarding":
		case "x11displayoffset":
		case "x11uselocalhost":
		case "permittty":
			b, err := strconv.ParseBool(parts[1])
			if err != nil {
				// TODO:
			}
			conf.permitTty = b
		case "printmotd":
		case "printlastlog":
		case "tcpkeepalive":
		case "permituserenvironment":
		case "compression":
		case "clientaliveinterval":
		case "clientalivecountmax":
		case "usedns":
		case "pidfile":
		case "maxstartups":
		case "permittunnel":
		case "chrootdirectory":
		case "versionaddendum":
		case "banner":
		case "subsystem":
		case "match":
		default:
		}
	}

	srv.Config = internalcaddyssh.ConfigList{
		internalcaddyssh.Configurator{
			ConfiguratorRaw: caddyconfig.JSONModuleObject(con, "loader", "provided", nil),
		},
	}
	sshApp := internalcaddyssh.SSH{
		Servers: map[string]*internalcaddyssh.Server{
			"srv0": srv,
		},
	}
	caddyConf := caddy.Config{
		AppsRaw: caddy.ModuleMap{
			"ssh": caddyconfig.JSON(sshApp, nil),
		},
	}
	result, err := json.Marshal(caddyConf)

	return result, nil, err
}

var _ caddyconfig.Adapter = (*adapter)(nil)
