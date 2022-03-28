#!/usr/bin/env sh
XCADDY_SKIP_BUILD=1 XCADDY_SKIP_CLEANUP=1 $(go env GOPATH)/bin/xcaddy build --with github.com/mohammed90/caddy-ssh
mv /tmp/buildenv_* custom-build