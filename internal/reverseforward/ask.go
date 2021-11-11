package reverseforward

import (
	"github.com/mohammed90/caddy-ssh/internal/ssh"
)

type PortForwardingAsker interface {
	Allow(ctx ssh.Context, destinationHost string, destinationPort uint32) bool
}
