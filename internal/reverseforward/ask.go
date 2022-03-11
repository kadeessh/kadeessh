package reverseforward

import (
	"github.com/mohammed90/caddy-ssh/internal/ssh"
)

// PortForwardingAsker is the interface necessary to ask whether a session is
// permitted to have reverse port-forwarding
type PortForwardingAsker interface {
	Allow(ctx ssh.Context, destinationHost string, destinationPort uint32) bool
}
