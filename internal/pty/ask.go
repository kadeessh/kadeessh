package pty

import "github.com/mohammed90/caddy-ssh/internal/ssh"

type PtyAsker interface {
	Allow(ctx ssh.Context, pty ssh.Pty) bool
}
