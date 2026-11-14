package caddyssh

import (
	_ "github.com/kadeessh/kadeessh/internal"
	_ "github.com/kadeessh/kadeessh/internal/actors"
	_ "github.com/kadeessh/kadeessh/internal/authentication"
	_ "github.com/kadeessh/kadeessh/internal/authentication/hashes"
	_ "github.com/kadeessh/kadeessh/internal/authentication/mfa"
	_ "github.com/kadeessh/kadeessh/internal/authentication/mfa/factors/recovery"
	_ "github.com/kadeessh/kadeessh/internal/authentication/mfa/factors/totp"
	_ "github.com/kadeessh/kadeessh/internal/authentication/mfa/store/caddy"
	_ "github.com/kadeessh/kadeessh/internal/authentication/os"
	_ "github.com/kadeessh/kadeessh/internal/authentication/static"
	_ "github.com/kadeessh/kadeessh/internal/authorization"
	_ "github.com/kadeessh/kadeessh/internal/banner"
	_ "github.com/kadeessh/kadeessh/internal/signer"
	_ "github.com/kadeessh/kadeessh/internal/subsystem"
)
