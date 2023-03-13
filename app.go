package caddyssh

import (
	_ "github.com/kadeessh/kadeessh/internal"
	_ "github.com/kadeessh/kadeessh/internal/actors"
	_ "github.com/kadeessh/kadeessh/internal/authentication"
	_ "github.com/kadeessh/kadeessh/internal/authentication/os"
	_ "github.com/kadeessh/kadeessh/internal/authentication/static"
	_ "github.com/kadeessh/kadeessh/internal/authorization"
	_ "github.com/kadeessh/kadeessh/internal/signer"
	_ "github.com/kadeessh/kadeessh/internal/subsystem"
)
