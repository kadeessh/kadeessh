# Caddy SSH

_This is still under heavy WIP._

Caddy SSH is an extensible, modular SSH server built as Caddy app. The project aims to provide an ssh server with safe, modern, and secure defaults.

## Install

You start by looking for the binaries in the [GitHub Releases](https://github.com/mohammed90/caddy-ssh/releases) page. Download the executable then place it somewhere in your PATH.

The other way is to build the project using [xcaddy](https://github.com/caddyserver/xcaddy) with the command:

```
xcaddy build --with github.com/mohammed90/caddy-ssh[@<version>]
```

where `[@<version>]` is optional and `<version>` may be replaced by the desired version.

## Sample Config

Note: The password is `test`. Once satisfied with the design and implementation, the packages will be extracted outside of `internal`.

<details>
<summary>Shell</summary>

```json
{
  "apps": {
    "ssh": {
      "grace_period": "2s",
      "servers": {
        "srv0": {
          "address": "tcp/0.0.0.0:2000-2012",
          "pty": {
            "pty": "allow"
          },
          "configs": [
            {
              "config": {
                "loader": "provided",
                "no_client_auth": false,
                "authentication": {
                  "username_password": {
                    "providers": {
                      "static": {
                        "accounts": [
                          {
                            "name": "user1",
                            "password": "JDJhJDE0JDcxOENoL2duS3FuR2VPRUpLa2lVM085Mk40T1JkcHBvQW4ycHU2c0FkMm1qLkhKejhzWG9t"
                          }
                        ]
                      }
                    }
                  }
                }
              }
            }
          ],
          "actors": [
            {
              "match": [
                {
                  "user": {
                    "users": [
                      "user1"
                    ]
                  }
                }
              ],
              "act": {
                "action": "shell",
                "shell": "zsh"
              }
            }
          ]
        }
      }
    }
  }
}
```

</details>  

<details>
<summary>Custom config based on remote address: allow local users, except root, to login without authentication</summary>

```json
{
  "apps": {
    "ssh": {
      "grace_period": "2s",
      "servers": {
        "srv0": {
          "address": "tcp/0.0.0.0:2000-2012",
          "pty": {
            "pty": "allow"
          },
          "configs": [
            {
              "match": [
                {
                  "remote_ip": {
                    "ranges": [
                      "192.168.0.0/16"
                    ]
                  }
                }
              ],
              "config": {
                "loader": "provided",
                "no_client_auth": true
              }
            },
            {
              "config": {
                "loader": "provided",
                "authentication": {
                  "deny_users": ["root"],
                  "public_key": {
                    "providers": {
                      "os": {}
                    }
                  }
                }
              }
            }
          ],
          "actors": [
            {
              "act": {
                "action": "shell",
                "shell": "bash"
              }
            }
          ]
        }
      }
    }
  }
}
```

</details>  

<details>
<summary>Jump server</summary>

As a jump server, the jump server establishes a local forwarding channel to upstream, per the documentation of the `-J` option, so we need to enable this in the config.

Reference:

> -J destination
    Connect to the target host by first making a ssh connection to the jump host described by destination and then establishing a TCP forwarding to the ultimate
    destination from there.  Multiple jump hops may be specified separated by comma characters.  This is a shortcut to specify a ProxyJump configuration directive.
    Note that configuration directives supplied on the command-line generally apply to the destination host and not any specified jump hosts.  Use ~/.ssh/config to
    specify configuration for jump hosts.

```json
{
  "apps": {
    "ssh": {
      "grace_period": "2s",
      "servers": {
        "srv0": {
          "address": "tcp/0.0.0.0:2000-2012",
          "configs": [
            {
              "config": {
                "loader": "provided",
                "signer": {
                  "module": "fallback"
                },
                "authentication": {
                  "public_key": {
                    "providers": {
                      "os": {}
                    }
                  }
                }
              }
            }
          ],
          "localforward": {
            "forward": "allow"
          },
        }
      }
    }
  }
}
```


</details>
<details>
<summary>Shell Session with Authorization Module</summary>

The app provides modular authorization process to control the session authorization based on the session context details. One of the authorization modules provided is `max_session`, which restricts the number of currently active sessions to a certain number. The other one is `public`, which grants access without restriction and is the default if none is provided. Here's an example config of how to restrict the server to authorize only 2 active sessions:

```json
{
  "apps": {
    "ssh": {
      "grace_period": "2s",
      "servers": {
        "srv0": {
          "address": "tcp/0.0.0.0:2000-2012",
          "authorize": {
            "authorizer": "max_session",
            "max_sessions": 2
          },
          "pty": {
            "pty": "allow"
          },
          "configs": [
            {
              "config": {
                "loader": "provided",
                "no_client_auth": false,
                "authentication": {
                  "public_key": {
                    "providers": {
                      "os": {}
                    }
                  }
                }
              }
            }
          ],
          "actors": [
            {
              "act": {
                "action": "shell",
                "shell": "zsh"
              }
            }
          ]
        }
      }
    }
  }
}
```

</details>

<details>

<summary>Shell Session with TOTP-based Password Authentication</summary>

The static password authentication does not currently support MFA due to upstream blocker. We can add a bit of dynamic password generation to the server by using the `totp` authentication provider. Use the command `caddy-ssh --username <username> --secret <secret>` to generate the PNG file of the QR code to use in your authenticator app and the base64-encoded secret to use in the configuration file of the ssh server. You can then use the below config, after plugging your username (as known to the OS) and base64-encoded secret, to run the caddy-ssh server. Use the OTP generated in your TOTP provider app when prompted for password.

```json
{
  "apps": {
    "ssh": {
      "grace_period": "2s",
      "servers": {
        "srv0": {
          "address": "tcp/0.0.0.0:2000-2012",
          "pty": {
            "pty": "allow"
          },
          "configs": [
            {
              "config": {
                "loader": "provided",
                "no_client_auth": false,
                "authentication": {
                  "username_password": {
                    "providers": {
                      "totp": {
                        "issuer": "caddy-ssh",
                        "accounts": [
                          {
                            "name": "user1",
                            "secret": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="
                          }
                        ]
                      }
                    }
                  }
                }
              }
            }
          ],
          "actors": [
            {
              "act": {
                "action": "shell",
                "shell": "zsh"
              }
            }
          ]
        }
      }
    }
  }
}
```
</details>

## Reference

- [OpenSSH Spec](https://www.openssh.com/specs.html)

## Questions

Q: I deny PTY allocation in config, but the is processed and executed anyways. Why?

A: This is a quirk in OpenSSH which defaults to `auto` if the `-t` option on the client (i.e. forcing tty allocation). It asks for the tty allocation but switches the mode to `auto` when denied and proceeds without the tty allocation request. The StackOverflow answer explaining the details is [here](https://stackoverflow.com/a/10346575).
