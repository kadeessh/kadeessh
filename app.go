package caddyssh

import (
	_ "github.com/mohammed90/caddy-ssh/internal"
	_ "github.com/mohammed90/caddy-ssh/internal/actors"
	_ "github.com/mohammed90/caddy-ssh/internal/authentication"
	_ "github.com/mohammed90/caddy-ssh/internal/authentication/os"
	_ "github.com/mohammed90/caddy-ssh/internal/authentication/static"
	_ "github.com/mohammed90/caddy-ssh/internal/authorization"
	_ "github.com/mohammed90/caddy-ssh/internal/signer"
	_ "github.com/mohammed90/caddy-ssh/internal/subsystem"
)
