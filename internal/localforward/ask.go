package localforward

import (
	"github.com/kadeessh/kadeessh/internal/ssh"
)

// PortForwardingAsker is the interface necessary to ask whether a session is
// permitted to have port-forwarding
type PortForwardingAsker interface {
	Allow(ctx ssh.Context, destinationHost string, destinationPort uint32) bool
}
