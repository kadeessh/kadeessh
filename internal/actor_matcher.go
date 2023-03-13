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

var _ ActorMatcher = ActorMatcherSet{}
var _ ActorMatcher = MatchRemoteIP{}
var _ ActorMatcher = MatchNot{}
var _ ActorMatcher = MatchUser{}
var _ ActorMatcher = MatchGroup{}
var _ ActorMatcher = MatchExtension{}
var _ ActorMatcher = MatchCriticalOption{}

func init() {
	caddy.RegisterModule(MatchRemoteIP{})
	caddy.RegisterModule(MatchNot{})
	caddy.RegisterModule(MatchUser{})
	caddy.RegisterModule(MatchGroup{})
	caddy.RegisterModule(MatchExtension{})
	caddy.RegisterModule(MatchCriticalOption{})
}

// ActorMatcher is an interface used to check whether an actor should act on the session
type ActorMatcher interface {
	ShouldAct(session.ActorMatchingContext) bool
}

// ActorMatcherSet is a set of matchers which must all match in order for the session to be matched and acted upon.
type ActorMatcherSet []ActorMatcher

// RawActorMatcherSet is a group of matcher sets in their raw, JSON form.
type RawActorMatcherSet []caddy.ModuleMap

// ShouldAct returns true if the session matches all matchers in ms or if there are no matchers.
func (ms ActorMatcherSet) ShouldAct(session session.ActorMatchingContext) bool {
	for _, m := range ms {
		if !m.ShouldAct(session) {
			return false
		}
	}
	return true
}

// ActorMatcherSets is a group of matcher sets capable of checking whether a session matches any of the sets.
type ActorMatcherSets []ActorMatcherSet

// AnyMatch returns true if session matches any of the matcher sets in ms or if there are no matchers, in which case the request always matches.
func (ms ActorMatcherSets) AnyMatch(session session.ActorMatchingContext) bool {
	for _, m := range ms {
		if m.ShouldAct(session) {
			return true
		}
	}
	return ms.Empty()
}

// Empty returns true if the set has no entries
func (ms ActorMatcherSets) Empty() bool {
	return len(ms) == 0
}

// FromInterface fills ms from an interface{} value obtained from LoadModule.
func (ms *ActorMatcherSets) FromInterface(matcherSets interface{}) error {
	for _, matcherSetIfaces := range matcherSets.([]map[string]interface{}) {
		var matcherSet ActorMatcherSet
		for _, matcher := range matcherSetIfaces {
			reqMatcher, ok := matcher.(ActorMatcher)
			if !ok {
				return fmt.Errorf("ActorMatcherSets: decoded module is not a Matcher: %#v", matcher)
			}
			matcherSet = append(matcherSet, reqMatcher)
		}
		*ms = append(*ms, matcherSet)
	}
	return nil
}

// MatchRemoteIP matches requests by client IP (or CIDR range).
type MatchRemoteIP struct {
	// The IPs or CIDR ranges to match.
	Ranges []string `json:"ranges,omitempty"`

	cidrs  []*net.IPNet
	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (MatchRemoteIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.actor_matchers.remote_ip",
		New: func() caddy.Module { return new(MatchRemoteIP) },
	}
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *MatchRemoteIP) Provision(ctx caddy.Context) error {
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

func (m MatchRemoteIP) getClientIP(r session.ActorMatchingContext) (net.IP, error) {
	remote := r.RemoteAddr().String()
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
func (m MatchRemoteIP) ShouldAct(r session.ActorMatchingContext) bool {
	clientIP, err := m.getClientIP(r)
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

// MatchNot matches requests by negating the results of its matcher
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
type MatchNot struct {
	MatcherSetsRaw []caddy.ModuleMap `json:"-" caddy:"namespace=ssh.actor_matchers"`
	MatcherSets    []ActorMatcherSet `json:"-"`
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (MatchNot) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.actor_matchers.not",
		New: func() caddy.Module { return new(MatchNot) },
	}
}

// UnmarshalJSON satisfies json.Unmarshaler. It puts the JSON
// bytes directly into m's MatcherSetsRaw field.
func (m *MatchNot) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &m.MatcherSetsRaw)
}

// MarshalJSON satisfies json.Marshaler by marshaling
// m's raw matcher sets.
func (m MatchNot) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.MatcherSetsRaw)
}

// Provision loads the matcher modules to be negated.
func (m *MatchNot) Provision(ctx caddy.Context) error {
	matcherSets, err := ctx.LoadModule(m, "MatcherSetsRaw")
	if err != nil {
		return fmt.Errorf("loading matcher sets: %v", err)
	}
	for _, modMap := range matcherSets.([]map[string]interface{}) {
		var ms ActorMatcherSet
		for _, modIface := range modMap {
			ms = append(ms, modIface.(ActorMatcher))
		}
		m.MatcherSets = append(m.MatcherSets, ms)
	}
	return nil
}

// ShouldAct returns true if r matches m. Since this matcher negates
// the embedded matchers, false is returned if any of its matcher
// sets return true.
func (m MatchNot) ShouldAct(r session.ActorMatchingContext) bool {
	for _, ms := range m.MatcherSets {
		if ms.ShouldAct(r) {
			return false
		}
	}
	return true
}

// MatchUser matches requests by username
type MatchUser struct {
	Users []string `json:"users,omitempty"`

	users  map[string]bool
	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (MatchUser) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.actor_matchers.user",
		New: func() caddy.Module { return new(MatchUser) },
	}
}

// Provision parses m's user list
func (m *MatchUser) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.users = make(map[string]bool)
	for _, str := range m.Users {
		m.users[str] = true
	}
	return nil
}

// ShouldAct returns true if session should act on m.
func (m MatchUser) ShouldAct(session session.ActorMatchingContext) bool {
	return m.users[session.User()]
}

// MatchGroup matches requests by user's group
type MatchGroup struct {
	Groups []string `json:"groups,omitempty"`

	groups map[string]bool
	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (MatchGroup) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.actor_matchers.group",
		New: func() caddy.Module { return new(MatchUser) },
	}
}

// Provision parses m's user list
func (m *MatchGroup) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.groups = make(map[string]bool)
	for _, str := range m.Groups {
		m.groups[str] = true
	}
	return nil
}

// ShouldAct returns true if session should act on m.
func (m MatchGroup) ShouldAct(session session.ActorMatchingContext) bool {
	return m.groups[session.User()]
}

// MatchExtension matches request by SSH protocol extension
type MatchExtension map[string][]string

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (m MatchExtension) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.actor_matchers.extension",
		New: func() caddy.Module { return new(MatchExtension) },
	}
}

// ShouldAct returns true if the requested ssh protocol extension matches any of the listed extensions
func (m MatchExtension) ShouldAct(ctx session.ActorMatchingContext) bool {
	// lifted from github.com/caddyserver/caddy/v2/modules/caddyhttp/matchers.go:matchHeaders with modifications

	// TODO: embed replacers
	repl := ctx.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	match := false
	for ext, extval := range ctx.Permissions().Extensions {
		for field, allowedFieldVals := range m {
			if !strings.EqualFold(ext, field) {
				continue
			}
			// normalize the actual value
			actualFieldVal := strings.ToLower(extval)
			if len(allowedFieldVals) == 0 && actualFieldVal != "" {
				// a non-nil but empty list of allowed values means
				// match if the header field exists at all
				continue
			}
			if allowedFieldVals == nil && actualFieldVal == "" {
				// a nil list means match if the header does not exist at all
				continue
			}

			for _, allowedFieldVal := range allowedFieldVals {
				// normalize the allowed value
				allowedFieldVal = strings.ToLower(allowedFieldVal)
				if repl != nil {
					allowedFieldVal = repl.ReplaceAll(allowedFieldVal, "")
				}
				switch {
				case allowedFieldVal == "*":
					match = true
				case strings.HasPrefix(allowedFieldVal, "*") && strings.HasSuffix(allowedFieldVal, "*"):
					match = strings.Contains(actualFieldVal, allowedFieldVal[1:len(allowedFieldVal)-1])
				case strings.HasPrefix(allowedFieldVal, "*"):
					match = strings.HasSuffix(actualFieldVal, allowedFieldVal[1:])
				case strings.HasSuffix(allowedFieldVal, "*"):
					match = strings.HasPrefix(actualFieldVal, allowedFieldVal[:len(allowedFieldVal)-1])
				default:
					match = actualFieldVal == allowedFieldVal
				}
				if match {
					return match
				}
			}
		}
	}
	return false
}

// MatchCriticalOption matches request by the value of critical-option of the certificate/user
type MatchCriticalOption map[string][]string

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (m MatchCriticalOption) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.actor_matchers.critical_option",
		New: func() caddy.Module { return new(MatchCriticalOption) },
	}
}

// ShouldAct returns true if any of the listed critical-options are in the critical-option of the certificate/user
func (m MatchCriticalOption) ShouldAct(ctx session.ActorMatchingContext) bool {
	// lifted from github.com/caddyserver/caddy/v2/modules/caddyhttp/matchers.go:matchHeaders with modifications

	// TODO: embed replacers
	repl := ctx.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	match := false
	for ext, extval := range ctx.Permissions().CriticalOptions {
		for field, allowedFieldVals := range m {
			if !strings.EqualFold(ext, field) {
				continue
			}
			// normalize the actual value
			actualFieldVal := strings.ToLower(extval)
			if len(allowedFieldVals) == 0 && actualFieldVal != "" {
				// a non-nil but empty list of allowed values means
				// match if the header field exists at all
				continue
			}
			if allowedFieldVals == nil && actualFieldVal == "" {
				// a nil list means match if the header does not exist at all
				continue
			}

			for _, allowedFieldVal := range allowedFieldVals {
				// normalize the allowed value
				allowedFieldVal = strings.ToLower(allowedFieldVal)
				if repl != nil {
					allowedFieldVal = repl.ReplaceAll(allowedFieldVal, "")
				}
				switch {
				case allowedFieldVal == "*":
					match = true
				case strings.HasPrefix(allowedFieldVal, "*") && strings.HasSuffix(allowedFieldVal, "*"):
					match = strings.Contains(actualFieldVal, allowedFieldVal[1:len(allowedFieldVal)-1])
				case strings.HasPrefix(allowedFieldVal, "*"):
					match = strings.HasSuffix(actualFieldVal, allowedFieldVal[1:])
				case strings.HasSuffix(allowedFieldVal, "*"):
					match = strings.HasPrefix(actualFieldVal, allowedFieldVal[:len(allowedFieldVal)-1])
				default:
					match = actualFieldVal == allowedFieldVal
				}
				if match {
					return match
				}
			}
		}
	}
	return false
}
