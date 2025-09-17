package reverseforward

import (
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/ssh"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(RemoteIP{})
}

// RemoteIP matches requests by client IP (or CIDR range).
type RemoteIP struct {
	// The IPs or CIDR ranges to match.
	Ranges []string `json:"ranges,omitempty"`

	cidrs  []*net.IPNet
	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (RemoteIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.ask.reverseforward.remote_ip",
		New: func() caddy.Module { return new(RemoteIP) },
	}
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *RemoteIP) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	for _, str := range m.Ranges {
		if strings.Contains(str, "/") {
			_, ipNet, err := net.ParseCIDR(str)
			if err != nil {
				return fmt.Errorf("parsing CIDR expression: %v", err)
			}
			m.cidrs = append(m.cidrs, ipNet)
		} else {
			ip := net.ParseIP(str)
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", str)
			}
			mask := len(ip) * 8
			m.cidrs = append(m.cidrs, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(mask, mask),
			})
		}
	}
	return nil
}

func (m RemoteIP) getClientIP(ctx ssh.Context) (net.IP, error) {
	remote := ctx.RemoteAddr().String()
	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid client IP address: %s", ipStr)
	}
	return ip, nil
}

// ShouldAct returns true if r matches m.
func (m RemoteIP) Allow(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
	clientIP, err := m.getClientIP(ctx)
	if err != nil {
		m.logger.Error("getting client IP", zap.Error(err))
		return false
	}
	for _, ipRange := range m.cidrs {
		if ipRange.Contains(clientIP) {
			return true
		}
	}
	return false
}

var (
	_ caddy.Provisioner   = (*RemoteIP)(nil)
	_ PortForwardingAsker = RemoteIP{}
)
