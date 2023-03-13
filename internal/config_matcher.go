package internalcaddyssh

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
	"go.uber.org/zap"
)

var _ ConfigMatcher = ConfigMatcherSet{}
var _ ConfigMatcher = MatchConfigRemoteIP{}
var _ ConfigMatcher = MatchConfigLocalIP{}
var _ ConfigMatcher = MatchConfigNot{}

func init() {
	caddy.RegisterModule(MatchConfigRemoteIP{})
	caddy.RegisterModule(MatchConfigNot{})
	caddy.RegisterModule(MatchConfigLocalIP{})
}

// ConfigMatcher should return true if the the connection needs to be configured by the accompanying set
type ConfigMatcher interface {
	ShouldConfigure(session.ConnConfigMatchingContext) bool
}

// ConfigMatcherSet is a set of matchers which must all match in order for the session to be matched and the server is configured.
type ConfigMatcherSet []ConfigMatcher

// RawConfigMatcherSet is a group of matcher sets in their raw, JSON form.
type RawConfigMatcherSet []caddy.ModuleMap

// ShouldConfigure returns true if the session matches all matchers in ms or if there are no matchers.
func (ms ConfigMatcherSet) ShouldConfigure(ctx session.ConnConfigMatchingContext) bool {
	for _, m := range ms {
		if !m.ShouldConfigure(ctx) {
			return false
		}
	}
	return true
}

// ConfigMatcherSets is a group of matcher sets capable of checking whether a session matches any of the sets.
type ConfigMatcherSets []ConfigMatcherSet

// AnyMatch returns true if session matches any of the matcher sets in ms or if there are no matchers, in which case the request always matches.
func (ms ConfigMatcherSets) AnyMatch(ctx session.ConnConfigMatchingContext) bool {
	for _, m := range ms {
		if m.ShouldConfigure(ctx) {
			return true
		}
	}
	return ms.Empty()
}

// Empty returns true if the set has no entries
func (ms ConfigMatcherSets) Empty() bool {
	return len(ms) == 0
}

// FromInterface fills ms from an interface{} value obtained from LoadModule.
func (ms *ConfigMatcherSets) FromInterface(matcherSets interface{}) error {
	for _, matcherSetIfaces := range matcherSets.([]map[string]interface{}) {
		var matcherSet ConfigMatcherSet
		for _, matcher := range matcherSetIfaces {
			reqMatcher, ok := matcher.(ConfigMatcher)
			if !ok {
				return fmt.Errorf("ConfigMatcherSets: decoded module is not a Matcher: %T", matcher)
			}
			matcherSet = append(matcherSet, reqMatcher)
		}
		*ms = append(*ms, matcherSet)
	}
	return nil
}

// MatchConfigRemoteIP matches requests by client IP (or CIDR range).
type MatchConfigRemoteIP struct {
	// The IPs or CIDR ranges to match.
	Ranges []string `json:"ranges,omitempty"`

	cidrs  []*net.IPNet
	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (MatchConfigRemoteIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.config_matchers.remote_ip",
		New: func() caddy.Module { return new(MatchConfigRemoteIP) },
	}
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *MatchConfigRemoteIP) Provision(ctx caddy.Context) error {
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

func (m MatchConfigRemoteIP) getClientIP(ctx session.ConnConfigMatchingContext) (net.IP, error) {
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

// ShouldConfigure returns true if ctx should configure m.
func (m MatchConfigRemoteIP) ShouldConfigure(ctx session.ConnConfigMatchingContext) bool {
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

// MatchConfigLocalIP matches requests by local IP (or CIDR range).
type MatchConfigLocalIP struct {
	// The IPs or CIDR ranges to match.
	Ranges []string `json:"ranges,omitempty"`

	cidrs  []*net.IPNet
	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (MatchConfigLocalIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.config_matchers.local_ip",
		New: func() caddy.Module { return new(MatchConfigRemoteIP) },
	}
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *MatchConfigLocalIP) Provision(ctx caddy.Context) error {
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

func (m MatchConfigLocalIP) getLocalIP(ctx session.ConnConfigMatchingContext) (net.IP, error) {
	remote := ctx.LocalAddr().String()
	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid local IP address: %s", ipStr)
	}
	return ip, nil
}

// ShouldConfigure returns true if ctx should configure m.
func (m MatchConfigLocalIP) ShouldConfigure(ctx session.ConnConfigMatchingContext) bool {
	localIP, err := m.getLocalIP(ctx)
	if err != nil {
		m.logger.Error("getting local IP", zap.Error(err))
		return false
	}
	for _, ipRange := range m.cidrs {
		if ipRange.Contains(localIP) {
			return true
		}
	}
	return false
}

// MatchConfigNot matches requests by negating the results of its matcher
// sets. A single "not" matcher takes one or more matcher sets. Each
// matcher set is OR'ed; in other words, if any matcher set returns
// true, the final result of the "not" matcher is false. Individual
// matchers within a set work the same (i.e. different matchers in
// the same set are AND'ed).
//
// NOTE: The generated docs which describe the structure of this
// module are wrong because of how this type unmarshals JSON in a
// custom way. The correct structure is:
//
// ```json
// [
//
//	{},
//	{}
//
// ]
// ```
//
// where each of the array elements is a matcher set, i.e. an
// object keyed by matcher name.
type MatchConfigNot struct {
	MatcherSetsRaw []caddy.ModuleMap  `json:"-" caddy:"namespace=ssh.config_matchers"`
	MatcherSets    []ConfigMatcherSet `json:"-"`
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (MatchConfigNot) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.config_matchers.not",
		New: func() caddy.Module { return new(MatchConfigNot) },
	}
}

func (m *MatchConfigNot) Provision(ctx caddy.Context) error {
	matcherSets, err := ctx.LoadModule(m, "MatcherSetsRaw")
	if err != nil {
		return fmt.Errorf("loading matcher sets: %v", err)
	}
	for _, modMap := range matcherSets.([]map[string]interface{}) {
		var ms ConfigMatcherSet
		for _, modIface := range modMap {
			ms = append(ms, modIface.(ConfigMatcher))
		}
		m.MatcherSets = append(m.MatcherSets, ms)
	}
	return nil
}

// ShouldConfigure returns true if r matches m. Since this matcher negates
// the embedded matchers, false is returned if any of its matcher
// sets return true.
func (m MatchConfigNot) ShouldConfigure(ctx session.ConnConfigMatchingContext) bool {
	for _, ms := range m.MatcherSets {
		if ms.ShouldConfigure(ctx) {
			return false
		}
	}
	return true
}

// UnmarshalJSON satisfies json.Unmarshaler. It puts the JSON
// bytes directly into m's MatcherSetsRaw field.
func (m *MatchConfigNot) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &m.MatcherSetsRaw)
}

// MarshalJSON satisfies json.Marshaler by marshaling
// m's raw matcher sets.
func (m MatchConfigNot) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.MatcherSetsRaw)
}
