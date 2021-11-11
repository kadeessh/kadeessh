# Caddy SSH

This is still under heavy WIP.

## Sample Config

Note: The password is `test`. Once satisfied with the design and implementation, the packages will be extracted outside of `internal`.

<details>

<summary>Run command and exit</summary>

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
                "signer": {
                  "module": "fallback"
                },
                "no_client_auth": false,
                "authentication": {
                  "username_password": {
                    "providers": {
                      "static": {
                        "accounts": [
                          {
                            "name": "user",
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
                      "user"
                    ]
                  }
                }
              ],
              "act": {
                "action": "command",
                "cmd": "go",
                "args": [
                  "version"
                ]
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

## Reference

- [OpenSSH Spec](https://www.openssh.com/specs.html)

## Questions

Q: I deny PTY allocation in config, but the is processed and executed anyways. Why?

A: This is a quirk in OpenSSH which defaults to `auto` if the `-t` option on the client (i.e. forcing tty allocation). It asks for the tty allocation but switches the mode to `auto` when denied and proceeds without the tty allocation request. The StackOverflow answer explaining the details is [here](https://stackoverflow.com/a/10346575).
