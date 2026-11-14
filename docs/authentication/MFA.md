# Multi-Factor Authentication

This is the operator guide for Kadeessh MFA. For a code-level walkthrough,
read [MFA_DESIGN.md](MFA_DESIGN.md). For the current security review and
review checklist, read [MFA_REVIEW.md](MFA_REVIEW.md).

## What MFA does

MFA wraps an existing primary authentication flow:

1. A password, public key, or interactive provider authenticates the user.
2. Kadeessh resolves the provider's canonical username.
3. MFA decides whether to allow the connection, require enrollment, or
   require an existing second factor.
4. Required MFA prompts use SSH `keyboard-interactive`.

MFA is disabled when the `authentication.mfa` block is absent.

### Behavior at a glance

| Account state | Result after primary authentication |
| --- | --- |
| Enrolled | Require TOTP or a recovery code. |
| Unenrolled, inside grace period | Allow login, record `FirstSeenAt`, and emit `mfa.grace_bypass`. |
| Unenrolled, grace expired or zero | Require enrollment before granting the session. |
| Touch-required `sk-*` key and `sk_satisfies_mfa: true` | Treat the hardware-key assertion as MFA. |
| `sk-*` key with `no-touch-required` | Do not bypass normal MFA. |
| Active lockout | Reject before showing an MFA prompt. |
| MFA storage error | Reject authentication. |

After MFA succeeds, the session is marked as authenticated for the actor
layer. This prevents the enrollment actor from running again after an
auth-time enrollment or hardware-key bypass.

## Minimal configuration

This example enables MFA and sends users who are still in their grace period
to the full-terminal enrollment actor:

```json
{
  "apps": {
    "ssh": {
      "servers": {
        "srv0": {
          "address": "tcp/0.0.0.0:2222",
          "pty": { "pty": "allow" },
          "configs": [
            {
              "config": {
                "loader": "provided",
                "authentication": {
                  "public_key": {
                    "providers": {
                      "os": {}
                    }
                  },
                  "mfa": {}
                }
              }
            }
          ],
          "actors": [
            {
              "match": [
                {
                  "mfa_status": {
                    "statuses": ["unenrolled", "pending"]
                  }
                }
              ],
              "act": { "action": "mfa_enroll" },
              "final": true
            },
            {
              "act": { "action": "shell" }
            }
          ]
        }
      }
    }
  }
}
```

An empty `"mfa": {}` block uses these defaults:

| Setting | Default |
| --- | --- |
| Factors | TOTP and recovery codes |
| Store | Caddy storage |
| Grace period | 30 days (`"720h"`) |
| Hardware key satisfies MFA | `true`, but only when user presence is required |
| Failed attempts | 5 in 15 minutes |
| Lockout | 30 seconds |
| Verification order | TOTP, then recovery codes |

## Configuration reference

```json
"mfa": {
  "policy": {
    "grace_period": "720h",
    "sk_satisfies_mfa": true,
    "max_failed_attempts": 5,
    "attempts_window": "15m",
    "lockout_duration": "30s"
  },
  "factors": {
    "totp": {
      "issuer": "Kadeessh",
      "digits": 6,
      "period": 30,
      "algorithm": "SHA256",
      "skew": 1
    },
    "recovery_codes": {
      "count": 10,
      "code_length": 10
    }
  },
  "verify_preference": ["totp", "recovery_codes"]
}
```

### Policy

- `grace_period`: time from the first successful primary authentication until
  enrollment becomes mandatory. Set `"0s"` for immediate enrollment.
- `sk_satisfies_mfa`: allows a touch-required OpenSSH FIDO/U2F key to satisfy
  MFA. Authorized-key or certificate permissions containing
  `no-touch-required` disable this bypass.
- `max_failed_attempts`: failures allowed in the rolling attempt window.
- `attempts_window`: rolling window used for the failure count.
- `lockout_duration`: denial period after reaching the failure threshold.

Negative policy values are rejected during provisioning.

### Store

The `store` field selects an MFA enrollment-store module. It can normally be
omitted because MFA defaults to the Caddy-backed store:

```json
"store": {
  "backend": "caddy"
}
```

The outer `store` is the field on the MFA configuration. Its `backend` field
is Caddy's module selector and chooses
`ssh.authentication.mfa.stores.caddy`.

The selected Caddy store uses the server's application-level Caddy storage by
default. Its optional `storage` field selects a different underlying
`caddy.storage` module:

```json
"store": {
  "backend": "caddy",
  "storage": {
    "module": "<caddy-storage-module>",
    "...": "module-specific configuration"
  }
}
```

In code, these layers correspond to:

- `mfa.Config.StoreRaw` (`json:"store"`, module key `backend`) for the MFA
  enrollment-store module;
- `caddystore.Store.StorageRaw` (`json:"storage"`) for its underlying Caddy
  storage module.

### TOTP

- `issuer`: label shown by the authenticator application.
- `digits`: `6` or `8`.
- `period`: code lifetime in seconds.
- `algorithm`: `SHA256` or `SHA512`. `SHA1` is rejected.
- `skew`: number of periods accepted before and after the current period.

The enrolled TOTP settings are stored with each user's factor. Changing the
server defaults affects new enrollments, not existing records.

Each successful TOTP verification persists the accepted counter. The same
counter cannot authenticate a second connection, even when it is still within
the configured skew window.

### Recovery codes

- `count`: number of codes generated during enrollment.
- `code_length`: random byte length before base32 encoding.
- `argon2_time`, `argon2_memory`, `argon2_threads`: hashing parameters.

Users enter recovery codes as `r-<code>` or `-r<code>`. Codes are stored as
Argon2id hashes and are consumed once.

### Verification order

`verify_preference` controls the order in which configured factors receive an
unprefixed response. A recovery-code prefix always tries `recovery_codes`
first.

## Enrollment paths

### Actor enrollment

The `mfa_enroll` actor runs after SSH authentication and can render a QR code
in the terminal. Use it with `mfa_status` values `unenrolled` and `pending`,
and normally mark it `final` so the user reconnects after enrollment.

`skip_when_enrolled` defaults to `true`. If the record changes while the
wizard is running, the actor refuses to replace it. Setting
`skip_when_enrolled: false` explicitly permits replacement and emits
`mfa.enrollment_replaced`.

### Auth-time enrollment

When grace is zero or expired, MFA returns SSH partial success and runs the
enrollment wizard over `keyboard-interactive` before any session is granted.
It displays the QR code, URI, and secret, verifies one TOTP value, generates
recovery codes when configured, and persists the record.

The confirmation TOTP counter is stored, so that same code cannot immediately
authenticate another connection.

## Verification and lockout

Enrolled users see:

```text
Authenticator code (or recovery code prefixed with r-):
```

Verification and replay-state persistence happen inside one per-user storage
transaction:

- TOTP stores `last_accepted_counter`.
- Recovery codes store `used_at`.
- Success resets failures and updates `last_used_at`.
- A persistence failure rejects authentication.

Failed responses increment the rolling failure count. Once the configured
threshold is reached, later authentication attempts are rejected until
`locked_until`.

## Actor status values

| Status | Meaning |
| --- | --- |
| `enrolled` | MFA completed for this connection, or the loaded record has factors. |
| `unenrolled` | No enrollment snapshot exists for the connection. |
| `pending` | A record has `FirstSeenAt` but no factors. |

On the first grace-period login, the actor sees `unenrolled` because
`FirstSeenAt` is persisted after the initial snapshot is loaded. Later
grace-period logins see `pending`.

## Storage

Default Caddy storage keys:

```text
ssh/mfa/seal.key
ssh/mfa/<server>/<username>.json
```

The store validates server and username path components. Record mutations use
`certmagic.Storage.Lock` with a per-user lock.

The seal key protects TOTP secrets with `nacl/secretbox`. In the default
layout, the key and records share a storage namespace. Sealing therefore
protects isolated record disclosure or backups that exclude the key; it does
not protect a complete storage-backend compromise.

Do not delete or replace `seal.key` by itself. Existing TOTP records will fail
closed because they cannot be decrypted. Rotation requires record migration
or resetting affected enrollments.

## Admin CLI

The CLI supports filesystem-backed storage only:

```text
kadeessh mfa list --server srv0
kadeessh mfa status alice --server srv0
kadeessh mfa reset alice --server srv0 --yes
```

- `list` and `status` inspect records.
- `reset` deletes a record; it does not enroll a user.
- `--storage-root` defaults to `$XDG_DATA_HOME/caddy`, or
  `~/.local/share/caddy` when `XDG_DATA_HOME` is unset.
- `--server` is required when the CLI finds more than one server directory.

The CLI accesses files directly and does not use the running server's storage
lock or audit logger. Coordinate reset operations with the server and shared
storage, and capture command execution in the operator audit system.

## Audit events

Server logs use an `event` field and include the canonical `user` and, where a
live connection exists, `remote_address`.

| Event | Additional fields |
| --- | --- |
| `mfa.verification_succeeded` | `factor` |
| `mfa.verification_failed` | |
| `mfa.verification_error` | error |
| `mfa.enrollment_created` | |
| `mfa.enrollment_replaced` | |
| `mfa.lockout_started` | `locked_until` |
| `mfa.lockout_denied` | `locked_until` |
| `mfa.grace_bypass` | `enrollment_deadline` |
| `mfa.sk_bypass` | `key_type`, `key_fingerprint` |

Forward these logs to durable, append-only storage if they are required for
incident response or compliance.

## Operational limits

- Clients must permit `keyboard-interactive` when a TOTP or enrollment prompt
  is required.
- Non-interactive SFTP automation cannot answer these prompts. Use an
  appropriate touch-required hardware-key policy or another deployment design.
- `interactive` as both the primary flow and MFA transport deserves dedicated
  integration testing before production use.
- The CLI cannot enroll users, regenerate only recovery codes, rotate the seal
  key, or operate on non-filesystem storage.
- Push factors, second-factor PAM, and standalone WebAuthn are not implemented.

## Review and validation

Validate a configuration before starting listeners:

```text
kadeessh validate --config kadeessh.json
```

For code review, continue with [MFA_DESIGN.md](MFA_DESIGN.md). It maps each
step above to the implementing file and function.
