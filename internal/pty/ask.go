package pty

import "github.com/kadeessh/kadeessh/internal/ssh"

// PtyAsker is the interface necessary to ask whether a session is
// permitted to have PTY
type PtyAsker interface {
	Allow(ctx ssh.Context, pty ssh.Pty) bool
}
