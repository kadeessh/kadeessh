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

	internalcaddyssh "github.com/kadeessh/kadeessh/internal"
	"github.com/kadeessh/kadeessh/internal/authentication"
	"github.com/kadeessh/kadeessh/internal/pty"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func init() {
	caddyconfig.RegisterAdapter("sshd_config", adapter{})
}

type adapter struct{}

var trueRegex = regexp.MustCompile(`(?i)true|yes`)

func (a adapter) Adapt(body []byte, options map[string]interface{}) ([]byte, []caddyconfig.Warning, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(body))
	filename, ok := options["filename"].(string)
	if !ok {
		filename = ""
	}
	if filename == "" {
		filename = "<sshd_config>"
	}
	srv := &internalcaddyssh.Server{}
	con := internalcaddyssh.ProvidedConfig{}

	var port int64 = 22
	var listenAddresses []string
	var hostKeys []string
	var permitRootLogin string
	var allowAgentForwarding bool
	var allowTCPForwarding bool
	var permitTTY bool
	subsystems := make(map[string]json.RawMessage)

	lineCounter := 0
	var warnings []caddyconfig.Warning
	for scanner.Scan() {
		lineCounter++
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 0 && line[0] == '#' {
			continue // it's a comment
		}
		// sshd_config allows key without value, which means 'yes'
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		if len(parts) == 1 {
			parts = append(parts, "yes")
		}
		if len(parts) == 1 {
			return nil, nil, fmt.Errorf("The line contains only 1 part")
		}

		switch strings.ToLower(parts[0]) {
		case "port":
			i, err := strconv.ParseInt(parts[1], 10, 32)
			if err != nil {
				return nil, []caddyconfig.Warning{{Message: fmt.Sprintf("invalid port: %s", parts[1])}}, nil
			}
			port = i
		case "addressfamily":
			// Not directly supported, Caddy addresses handle IPv4/IPv6.
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "listenaddress":
			listenAddresses = append(listenAddresses, parts[1])
		case "hostkey":
			hostKeys = append(hostKeys, parts[1])
		case "rekeylimit":
			// Not exposed in ProvidedConfig
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "syslogfacility":
			// Caddy handles logging; this is not directly translatable.
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "loglevel":
			// TODO: implement
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "logingracetime":
			// No direct equivalent for the whole connection, but IdleTimeout exists.
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "permitrootlogin":
			permitRootLogin = parts[1]
		case "strictmodes":
			// TODO: assess
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "maxauthtries":
			mat, err := strconv.ParseInt(parts[1], 10, 32)
			if err != nil {
				return nil, []caddyconfig.Warning{{Message: fmt.Sprintf("invalid MaxAuthTries: %s", parts[1])}}, nil
			}
			con.MaxAuthTries = int(mat)
		case "maxsessions":
			// TODO:  implement; This can be implemented with an authorizer module
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "pubkeyauthentication":
			if !trueRegex.MatchString(parts[1]) {
				if con.Authentication == nil {
					continue
				}
				con.Authentication.PublicKey = nil
			} else {
				if con.Authentication == nil {
					con.Authentication = &authentication.Config{}
				}
				if con.Authentication.PublicKey == nil {
					con.Authentication.PublicKey = &authentication.PublicKeyFlow{
						ProvidersRaw: caddy.ModuleMap{
							"os": json.RawMessage(`{}`),
						},
					}
				}
			}
		case "authorizedkeysfile":
			// TODO: implement
			// The 'os' provider for public_key auth implicitly handles this.
			// We could potentially parse this to configure a 'file' provider.
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "authorizedprincipalsfile":
			// TODO: implement
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "authorizedkeyscommand":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "authorizedkeyscommanduser":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "hostbasedauthentication":
			// Not supported by crypto/ssh, so not supported here.
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "ignoreuserknownhosts":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "ignorerhosts":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "passwordauthentication":
			if !trueRegex.MatchString(parts[1]) {
				if con.Authentication == nil {
					continue
				}
				con.Authentication.UsernamePassword = nil
			} else {
				if con.Authentication == nil {
					con.Authentication = &authentication.Config{}
				}
				con.Authentication.UsernamePassword = &authentication.PasswordAuthFlow{
					ProvidersRaw: caddy.ModuleMap{
						"os": json.RawMessage(`{}`),
					},
				}
			}
		case "permitemptypasswords":
			if trueRegex.MatchString(parts[1]) {
				if con.Authentication == nil {
					con.Authentication = &authentication.Config{}
				}
				if con.Authentication.UsernamePassword == nil {
					con.Authentication.UsernamePassword = &authentication.PasswordAuthFlow{}
				}
				con.Authentication.UsernamePassword.PermitEmptyPasswords = true
			}
		case "kbdinteractiveauthentication":
			// TODO: implement
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "kerberosauthentication":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "kerberosorlocalpasswd":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "kerberosticketcleanup":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "kerberosgetafstoken":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "gssapiauthentication":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "gssapicleanupcredentials":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "usepam":
			// PAM can be a provider for password/interactive auth.
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "allowagentforwarding":
			allowAgentForwarding = trueRegex.MatchString(parts[1])
		case "allowtcpforwarding":
			allowTCPForwarding = trueRegex.MatchString(parts[1])
		case "gatewayports":
			// This is a more detailed setting for remote forwarding.
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "x11forwarding":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "x11displayoffset":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "x11uselocalhost":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "permittty":
			permitTTY = trueRegex.MatchString(parts[1])
		case "printmotd":
			// Can be mapped to banner module.
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "printlastlog":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "tcpkeepalive":
			// This is on by default in Go's net package.
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "permituserenvironment":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "compression":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "clientaliveinterval":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "clientalivecountmax":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "usedns":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "pidfile":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "maxstartups":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "permittunnel":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "chrootdirectory":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "versionaddendum":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		case "banner":
			con.BannerRaw = caddyconfig.JSONModuleObject(
				map[string]interface{}{"file": parts[1]},
				"engine", "file", nil,
			)
		case "subsystem":
			if len(parts) >= 3 {
				subsystemName := parts[1]
				command := strings.Join(parts[2:], " ")
				subsystems[subsystemName] = caddyconfig.JSONModuleObject(
					map[string]interface{}{"command": command},
					"handler", "command", nil,
				)
			}
		case "match":
			warnings = append(warnings, makeWarning(filename, lineCounter, parts[0]))
		default:
			warnings = append(warnings, caddyconfig.Warning{
				File:      filename,
				Line:      lineCounter,
				Directive: parts[0],
				Message:   fmt.Sprintf("unrecognized directive: %s", parts[0]),
			})
		}
	}

	if len(listenAddresses) == 0 {
		listenAddresses = append(listenAddresses, net.JoinHostPort("0.0.0.0", strconv.FormatInt(port, 10)))
	} else {
		// Ensure all listen addresses include the port
		for i, addr := range listenAddresses {
			if !strings.Contains(addr, ":") {
				listenAddresses[i] = net.JoinHostPort(addr, strconv.FormatInt(port, 10))
			}
		}
	}
	// For simplicity, we'll just use the first listen address. Caddy can handle multiple servers.
	srv.Address = listenAddresses[0]

	if len(hostKeys) > 0 {
		con.SignerRaw = caddyconfig.JSONModuleObject(map[string]interface{}{"files": hostKeys}, "module", "file", nil)
	}

	if permitRootLogin != "" && permitRootLogin != "prohibit-password" && permitRootLogin != "yes" {
		if con.Authentication == nil {
			con.Authentication = &authentication.Config{}
		}
		con.Authentication.DenyUsers = []string{"root"}
	}

	if allowTCPForwarding {
		srv.LocalForwardRaw = json.RawMessage(`{"forward": "allow"}`)
		srv.ReverseForwardRaw = json.RawMessage(`{"forward": "allow"}`)
	}

	if permitTTY {
		srv.PtyAskRaw = json.RawMessage(`{"pty": "allow"}`)
	}

	// If PTY is allowed, we can assume a shell actor is desired.
	if permitTTY {
		srv.Actors = append(srv.Actors, internalcaddyssh.Actor{
			ActorRaw: caddyconfig.JSONModuleObject(pty.Shell{}, "action", "shell", nil),
		})
	}

	if allowAgentForwarding {
		// Agent forwarding is handled by the session actor, not a server-level config.
		// This would require a more complex actor setup, possibly with matching.
	}
	if len(subsystems) > 0 {
		srv.SubsystemRaw = subsystems
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

func makeWarning(filename string, line int, directive string) caddyconfig.Warning {
	return caddyconfig.Warning{
		File:      filename,
		Line:      line,
		Directive: directive,
		Message:   fmt.Sprintf("'%s' option is not directly supported. (%s)", directive, directive),
	}
}

var _ caddyconfig.Adapter = adapter{}
