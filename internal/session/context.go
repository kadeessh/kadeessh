package session

import (
	"context"
	"net"
	"sync"

	"github.com/kadeessh/kadeessh/internal/ssh"
)

// For compatibility reasons
var _ ssh.Context = Context(nil)

// ConnMetadata is our own interface compatible with ConnMetadata of github.com/gliderlabs/ssh
// to define our modules' requirements against an internal interface rather than external
type Context interface {
	// ssh.Context
	context.Context
	sync.Locker

	// User returns the username used when establishing the SSH connection.
	User() string

	// SessionID returns the session hash.
	SessionID() string

	// ClientVersion returns the version reported by the client.
	ClientVersion() string

	// ServerVersion returns the version reported by the server.
	ServerVersion() string

	// RemoteAddr returns the remote address for this connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the local address for this connection.
	LocalAddr() net.Addr

	// Permissions returns the Permissions object used for this connection.
	Permissions() *ssh.Permissions

	// SetValue allows you to easily write new values into the underlying context.
	SetValue(key, value interface{})
}

// ConnConfigMatchingContext is an interface of the data available for ConfigMatcher
type ConnConfigMatchingContext interface {
	// RemoteAddr returns the net.Addr of the client side of the connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the net.Addr of the server side of the connection.
	LocalAddr() net.Addr
}

// ActorMatchingContext is an interface of the data available for ActorMatcher
type ActorMatchingContext interface {
	// User returns the username used when establishing the SSH connection.
	User() string

	// RemoteAddr returns the net.Addr of the client side of the connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the net.Addr of the server side of the connection.
	LocalAddr() net.Addr

	// Environ returns a copy of strings representing the environment set by the
	// user for this session, in the form "key=value".
	Environ() []string

	// Command returns a shell parsed slice of arguments that were provided by the
	// user. Shell parsing splits the command string according to POSIX shell rules,
	// which considers quoting not just whitespace.
	Command() []string

	// RawCommand returns the exact command that was provided by the user.
	RawCommand() string

	// Subsystem returns the subsystem requested by the user.
	Subsystem() string

	// PublicKey returns the PublicKey used to authenticate. If a public key was not
	// used it will return nil.
	PublicKey() ssh.PublicKey

	// Context returns the connection's context. The returned context is always
	// non-nil and holds the same data as the Context passed into auth
	// handlers and callbacks.
	//
	// The context is canceled when the client's connection closes or I/O
	// operation fails.
	Context() context.Context

	// Permissions returns a copy of the Permissions object that was available for
	// setup in the auth handlers via the Context.
	Permissions() ssh.Permissions

	// Experimental:
	// Pty returns PTY information, a channel of window size changes, and a boolean
	// of whether or not a PTY was accepted for this session.
	Pty() (ssh.Pty, <-chan ssh.Window, bool)
}
