package internalcaddyssh

import (
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/session"
	"github.com/kadeessh/kadeessh/internal/ssh"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

func TestActorMatchers(t *testing.T) {
	logger := zap.NewNop()
	type testCase struct {
		name string
		ms   ActorMatcher
		args session.ActorMatchingContext
		want bool
	}
	tests := map[string][]testCase{
		"MatchUser": {
			{
				name: "user amongst approved users",
				ms: MatchUser{
					users: map[string]bool{
						"foo": true,
						"bar": true,
					},
					logger: logger,
				},
				args: fakeMatchingContext{user: func() string { return "foo" }},
				want: true,
			},
			{
				name: "empty approved user list",
				ms: MatchUser{
					logger: logger,
				},
				args: fakeMatchingContext{user: func() string { return "foo" }},
				want: false,
			},
			{
				name: "user not amongst approved users",
				ms: MatchUser{
					users: map[string]bool{
						"foo": true,
					},
					logger: logger,
				},
				args: fakeMatchingContext{user: func() string { return "bar" }},
				want: false,
			},
		},
		"MatchRemoteIP": {},
		"MatchNot":      {},
		"MatchExtension": {
			{
				name: "",
				ms: MatchExtension{
					"extension-1": {},
				},
				args: fakeMatchingContext{
					context: func() context.Context {
						return context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
					},
					permissions: func() ssh.Permissions {
						return ssh.Permissions{
							Permissions: &gossh.Permissions{
								Extensions: map[string]string{},
							},
						}
					},
				},
				want: false,
			},
			{
				name: "",
				ms: MatchExtension{
					"extension-1": {
						"no-match",
					},
				},
				args: fakeMatchingContext{
					context: func() context.Context {
						return context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
					},
					permissions: func() ssh.Permissions {
						return ssh.Permissions{
							Permissions: &gossh.Permissions{
								Extensions: map[string]string{
									"extension-1": "value",
								},
							},
						}
					},
				},
				want: false,
			},
			{
				name: "",
				ms: MatchExtension{
					"extension-1": {
						"match",
					},
				},
				args: fakeMatchingContext{
					context: func() context.Context {
						return context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
					},
					permissions: func() ssh.Permissions {
						return ssh.Permissions{
							Permissions: &gossh.Permissions{
								Extensions: map[string]string{
									"extension-1": "match",
								},
							},
						}
					},
				},
				want: true,
			},
		},
		"MatchCriticalOption": {
			{
				name: "",
				ms: MatchCriticalOption{
					"option-1": {},
				},
				args: fakeMatchingContext{
					context: func() context.Context {
						return context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
					},
					permissions: func() ssh.Permissions {
						return ssh.Permissions{
							Permissions: &gossh.Permissions{
								CriticalOptions: map[string]string{},
							},
						}
					},
				},
				want: false,
			},
			{
				name: "",
				ms: MatchCriticalOption{
					"option-1": {
						"no-match",
					},
				},
				args: fakeMatchingContext{
					context: func() context.Context {
						return context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
					},
					permissions: func() ssh.Permissions {
						return ssh.Permissions{
							Permissions: &gossh.Permissions{
								CriticalOptions: map[string]string{
									"option-1": "value",
								},
							},
						}
					},
				},
				want: false,
			},
			{
				name: "",
				ms: MatchCriticalOption{
					"option-1": {
						"match",
					},
				},
				args: fakeMatchingContext{
					context: func() context.Context {
						return context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
					},
					permissions: func() ssh.Permissions {
						return ssh.Permissions{
							Permissions: &gossh.Permissions{
								CriticalOptions: map[string]string{
									"option-1": "match",
								},
							},
						}
					},
				},
				want: true,
			},
		},
	}
	for k, tt := range tests {
		t.Run(k, func(t *testing.T) {
			for _, tt := range tt {
				t.Run(tt.name, func(t *testing.T) {
					if got := tt.ms.ShouldAct(tt.args); got != tt.want {
						t.Errorf("%T.ShouldAct() = %v, want %v", tt.ms, got, tt.want)
					}
				})
			}
		})
	}
}

func TestActorMatcherSet_ShouldAct(t *testing.T) {
	type args struct {
		session session.ActorMatchingContext
	}
	tests := []struct {
		name string
		ms   ActorMatcherSet
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ms.ShouldAct(tt.args.session); got != tt.want {
				t.Errorf("ActorMatcherSet.ShouldAct() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestActorMatcherSets_AnyMatch(t *testing.T) {
	type args struct {
		session session.ActorMatchingContext
	}
	tests := []struct {
		name string
		ms   ActorMatcherSets
		args args
		want bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ms.AnyMatch(tt.args.session); got != tt.want {
				t.Errorf("ActorMatcherSets.AnyMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestActorMatcherSets_FromInterface(t *testing.T) {
	type args struct {
		matcherSets interface{}
	}
	tests := []struct {
		name    string
		ms      *ActorMatcherSets
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.ms.FromInterface(tt.args.matcherSets); (err != nil) != tt.wantErr {
				t.Errorf("ActorMatcherSets.FromInterface() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatchNot_UnmarshalJSON(t *testing.T) {
	type fields struct {
		MatcherSetsRaw []caddy.ModuleMap
		MatcherSets    []ActorMatcherSet
	}
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MatchNot{
				MatcherSetsRaw: tt.fields.MatcherSetsRaw,
				MatcherSets:    tt.fields.MatcherSets,
			}
			if err := m.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("MatchNot.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatchNot_MarshalJSON(t *testing.T) {
	type fields struct {
		MatcherSetsRaw []caddy.ModuleMap
		MatcherSets    []ActorMatcherSet
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MatchNot{
				MatcherSetsRaw: tt.fields.MatcherSetsRaw,
				MatcherSets:    tt.fields.MatcherSets,
			}
			got, err := m.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchNot.MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MatchNot.MarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

type fakeMatchingContext struct {
	user        func() string
	remoteAddr  func() net.Addr
	localAddr   func() net.Addr
	environ     func() []string
	command     func() []string
	rawCommand  func() string
	subsystem   func() string
	publicKey   func() ssh.PublicKey
	context     func() context.Context
	permissions func() ssh.Permissions
	pty         func() (ssh.Pty, <-chan ssh.Window, bool)
}

// User returns the username used when establishing the SSH connection.
func (fmc fakeMatchingContext) User() string {
	return fmc.user()
}

// RemoteAddr returns the net.Addr of the client side of the connection.
func (fmc fakeMatchingContext) RemoteAddr() net.Addr {
	return fmc.remoteAddr()
}

// LocalAddr returns the net.Addr of the server side of the connection.
func (fmc fakeMatchingContext) LocalAddr() net.Addr {
	return fmc.localAddr()
}

// Environ returns a copy of strings representing the environment set by the
// user for this session, in the form "key=value".
func (fmc fakeMatchingContext) Environ() []string {
	return fmc.environ()
}

// Command returns a shell parsed slice of arguments that were provided by the
// user. Shell parsing splits the command string according to POSIX shell rules,
// which considers quoting not just whitespace.
func (fmc fakeMatchingContext) Command() []string {
	return fmc.command()
}

// RawCommand returns the exact command that was provided by the user.
func (fmc fakeMatchingContext) RawCommand() string {
	return fmc.rawCommand()
}

// Subsystem returns the subsystem requested by the user.
func (fmc fakeMatchingContext) Subsystem() string {
	return fmc.subsystem()
}

// PublicKey returns the PublicKey used to authenticate. If a public key was not
// used it will return nil.
func (fmc fakeMatchingContext) PublicKey() ssh.PublicKey {
	return fmc.publicKey()
}

// Context returns the connection's context. The returned context is always
// non-nil and holds the same data as the Context passed into auth
// handlers and callbacks.
//
// The context is canceled when the client's connection closes or I/O
// operation fails.
func (fmc fakeMatchingContext) Context() context.Context {
	return fmc.context()
}

// Permissions returns a copy of the Permissions object that was available for
// setup in the auth handlers via the Context.
func (fmc fakeMatchingContext) Permissions() ssh.Permissions {
	return fmc.permissions()
}

// Experimental:
// Pty returns PTY information, a channel of window size changes, and a boolean
// of whether or not a PTY was accepted for this session.
func (fmc fakeMatchingContext) Pty() (ssh.Pty, <-chan ssh.Window, bool) {
	return fmc.pty()
}
