#!/usr/bin/env sh
XCADDY_SKIP_BUILD=1 XCADDY_SKIP_CLEANUP=1 xcaddy build --with github.com/mohammed90/caddy-ssh
mv buildenv_* custom-build