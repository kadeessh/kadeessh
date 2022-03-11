package session

import (
	"net"

	"golang.org/x/crypto/ssh"
)

// For compatibility reasons
var _ ssh.ConnMetadata = ConnMetadata(nil)

// ConnMetadata is our own interface compatible with ConnMetadata of golang.org/x/crypto/ssh
// to define our modules' requirements against an internal interface rather than external
type ConnMetadata interface {
	// User returns the user ID for this connection.
	User() string

	// SessionID returns the session hash, also denoted by H.
	SessionID() []byte

	// ClientVersion returns the client's version string as hashed
	// into the session ID.
	ClientVersion() []byte

	// ServerVersion returns the server's version string as hashed
	// into the session ID.
	ServerVersion() []byte

	// RemoteAddr returns the remote address for this connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the local address for this connection.
	LocalAddr() net.Addr
}
