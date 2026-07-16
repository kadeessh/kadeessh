# Asciinema Session Recording

> **⚠️ Experimental.** This module is under active development. Its
> configuration surface (option names, defaults, on-disk temp-file layout,
> recovered storage key naming) and log field shapes may change in
> backwards-incompatible ways. Do not build long-term automation against it
> yet.

The `asciinema_recorder` actor wraps other handlers to record SSH session output in asciinema cast v2 format. Recordings are automatically saved to Caddy storage for later playback and audit purposes.

## Features

- **Output-only recording**: Only captures terminal output, not user input (for security)
- **Asciinema v2 format**: Compatible with asciinema player and other tools
- **Resize events**: PTY window changes are recorded as `"r"` events
- **Durable storage**: Periodic mid-session flushes bound data loss on crash
- **Truncation marker**: When size/duration limits are hit, a `"m"` marker event is written so consumers can detect truncation
- **Rich metadata**: Includes username, session ID, client IP, timestamp, and terminal dimensions
- **Configurable limits**: Set max recording size and duration
- **Error handling**: Choose whether to reject sessions or continue without recording on errors

## Configuration

### Basic Example

```json
{
  "act": {
    "action": "asciinema_recorder",
    "handler": {
      "action": "shell"
    }
  }
}
```

### Full Configuration

```json
{
  "act": {
    "action": "asciinema_recorder",
    "handler": {
      "action": "shell"
    },
    "max_size": 10485760,
    "max_duration": "1h",
    "flush_interval": "1s",
    "temp_dir": "/var/lib/kadeessh/recordings-in-progress",
    "recover_orphans": true,
    "on_recording_error": "continue",
    "include_metadata": true,
    "storage": {
      "module": "file_system",
      "root": "/var/lib/caddy"
    }
  }
}
```

## Configuration Options

### `handler` (required)

The wrapped handler that will handle the actual SSH session. This can be any valid actor like `shell`, `static_response`, etc. The nested handler uses the same `action` discriminator as any other actor in the `ssh.actors` namespace.

**Example:**
```json
"handler": {
  "action": "shell"
}
```

### `storage` (optional)

The Caddy storage module to save recordings. If not specified, the default Caddy storage is used.

**Default:** Default Caddy storage

**Example:**
```json
"storage": {
  "module": "file_system",
  "root": "/var/ssh/recordings"
}
```

### `max_size` (optional)

Maximum recording size in bytes. When the limit is reached, a truncation marker event (asciinema `"m"` type) is written to the cast and further output is not recorded, but the session continues normally. Zero means no limit.

**Default:** `0` (unlimited)

**Example:**
```json
"max_size": 10485760
```
*(10 MB limit)*

### `max_duration` (optional)

Maximum recording duration. When the time limit is reached, a truncation marker event is written and further output is not recorded, but the session continues normally. Zero means no limit.

**Default:** `0` (unlimited)

**Example:**
```json
"max_duration": "1h"
```

**Supported formats:** `"30s"`, `"5m"`, `"2h"`, etc.

### `flush_interval` (optional)

How often the buffered writer for the in-progress recording is flushed and fsynced to its local temp file. Bounds data loss on crash to roughly one interval. A negative value disables periodic fsync (the OS page cache may still persist writes, but there is no explicit sync until session close).

**Default:** `"1s"`

**Example:**
```json
"flush_interval": "5s"
```

### `temp_dir` (optional)

Local directory where in-progress recording temp files live during a session. Temp files are named `kadeessh-record-<pid>-<random>.cast`. On graceful session close each temp file is uploaded to storage and deleted. On crash or on upload failure the temp file remains on disk for recovery (see `recover_orphans`).

**Default:** OS temp directory (`os.TempDir()`)

**Example:**
```json
"temp_dir": "/var/lib/kadeessh/recordings-in-progress"
```

### `recover_orphans` (optional)

When `true`, at startup the module scans `temp_dir` for orphan cast files left by a previous crashed process and uploads them to storage. Files owned by the current process (matched by PID in the filename) are always skipped so a config reload cannot race with live sessions. The scan runs asynchronously and never fails startup.

Recovered files are placed at their original storage key when the header contains SSH metadata (`ssh/recordings/<date>/<user>-<sid>-recovered.cast`); files with unparseable or missing metadata fall back to `ssh/recordings/recovered/<original-tempfile-name>`.

**Default:** `true`

**Example:**
```json
"recover_orphans": false
```

### `on_recording_error` (optional)

Behavior when recording fails to initialize or save. Options:

- `"continue"`: Continue the session without recording (logs a warning)
- `"reject"`: Reject the session and return an error to the client

**Default:** `"continue"`

**Example:**
```json
"on_recording_error": "reject"
```

### `include_metadata` (optional)

Whether to include SSH session metadata in the recording header. When enabled, a tool-scoped `kadeessh` object is added to the cast header with:

- `user` — authenticated username
- `session_id` — SSH session identifier (hex)
- `client` — client address (`host:port`)
- `server` — server address (`host:port`)
- `client_version` — SSH client version string
- `pty_term` — requested terminal type when a PTY was allocated

The `title` field (`user@client (session: id)`) is also populated when metadata is enabled. The cast v2 `env` field is reserved for terminal environment variables (`TERM`) and is not used to carry SSH metadata.

**Default:** `true`

**Example:**
```json
"include_metadata": false
```

## Storage Path Structure

Recordings are organized by date:

```
ssh/recordings/{YYYY-MM-DD}/{username}-{session-id}.cast
```

**Example:**
```
ssh/recordings/2025-10-24/alice-a1b2c3d4e5f6.cast
ssh/recordings/2025-10-24/bob-f6e5d4c3b2a1.cast
```

### Filename sanitization

Both `{username}` and `{session-id}` are sanitized before being used in the storage key: characters outside `[A-Za-z0-9_-]` are replaced with `_`, leading/trailing underscore runs are trimmed, and each part is capped at 64 characters. Empty parts become `unknown`. A username like `../../etc/passwd` becomes `etc_passwd`, so client-controlled usernames cannot escape the recordings directory.

### Collision handling

If a recording already exists at the intended storage key (for example, a stale file left by a crashed session with a colliding ID), the new recording is written to a distinct key with a nanosecond suffix instead of silently overwriting the existing file.

This organization makes it easy to:
- Archive old recordings by date
- Find recordings for specific users
- Manage storage and retention policies

## Asciinema Cast Format

The recordings use asciinema cast v2 format, which consists of:

1. **Header line**: JSON object with metadata
2. **Event lines**: JSON arrays with `[timestamp, event_type, data]`

Event types emitted by this module:

- `"o"` — terminal output (stdout and stderr, interleaved in wall-clock order)
- `"r"` — PTY window resize; data is `"COLSxROWS"` (e.g. `"120x50"`)
- `"m"` — marker; used to signal truncation when a size or duration limit is hit

### Example Recording

```json
{"version": 2, "width": 80, "height": 24, "timestamp": 1730000000, "env": {"TERM": "xterm-256color"}, "title": "alice@192.168.1.100:54321 (session: a1b2c3d4e5f6)", "kadeessh": {"user": "alice", "client": "192.168.1.100:54321", "server": "10.0.0.1:22", "session_id": "a1b2c3d4e5f6", "client_version": "SSH-2.0-OpenSSH_9.0", "pty_term": "xterm-256color"}}
[0.123, "o", "Welcome to the server!\r\n"]
[1.456, "o", "$ "]
[2.001, "r", "120x50"]
[3.789, "o", "ls -la\r\n"]
```

The `kadeessh` field is a tool-scoped extension; asciinema players ignore unknown top-level fields.

## Playback

Recordings can be played back using:

### Asciinema CLI

```bash
asciinema play ssh/recordings/2025-10-24/alice-a1b2c3d4e5f6.cast
```

### Web Player

Embed in HTML using [asciinema-player](https://github.com/asciinema/asciinema-player):

```html
<script src="asciinema-player.min.js"></script>
<link rel="stylesheet" type="text/css" href="asciinema-player.css" />
<div id="player"></div>
<script>
  AsciinemaPlayer.create(
    '/recordings/2025-10-24/alice-a1b2c3d4e5f6.cast',
    document.getElementById('player')
  );
</script>
```

## Security Considerations

### What is Recorded

✅ **Recorded:**
- Terminal output (what the user sees)
- Stderr output
- Terminal escape sequences and formatting

❌ **NOT Recorded:**
- User keyboard input
- Passwords typed by the user
- SSH authentication credentials

### Privacy

Only output is captured to prevent sensitive data exposure. However, be aware that:

- Command output may contain sensitive information
- Environment variables or file contents may be displayed
- Configure appropriate access controls on the storage location
- Implement retention policies to automatically delete old recordings

## Use Cases

### Compliance and Auditing

Record administrative sessions for compliance with regulations like:
- SOC 2
- PCI DSS
- HIPAA
- ISO 27001

### Troubleshooting

Replay sessions to:
- Debug user-reported issues
- Understand what commands were executed
- Analyze system changes

### Training

Use recordings for:
- Creating documentation
- Training new team members
- Demonstrating procedures

## Complete Configuration Example

```json
{
  "apps": {
    "ssh": {
      "servers": {
        "production_server": {
          "address": "tcp/0.0.0.0:22",
          "pty": {
            "pty": "allow"
          },
          "configs": [
            {
              "config": {
                "loader": "provided",
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
              "matcher": {
                "user": ["admin", "ops"]
              },
              "act": {
                "action": "asciinema_recorder",
                "handler": {
                  "action": "shell"
                },
                "max_size": 52428800,
                "max_duration": "4h",
                "flush_interval": "1s",
                "temp_dir": "/var/lib/kadeessh/recordings-in-progress",
                "recover_orphans": true,
                "on_recording_error": "reject",
                "include_metadata": true
              }
            },
            {
              "act": {
                "action": "shell"
              }
            }
          ]
        }
      }
    }
  }
}
```

This configuration:
- Records sessions for `admin` and `ops` users only
- Limits recordings to 50 MB and 4 hours
- Rejects sessions if recording fails (ensures all admin sessions are recorded)
- Includes full metadata for audit trails
- Falls back to unrecorded shell for other users

## Monitoring

The recorder logs important events:

- **Info**: When recording is successfully saved
- **Warn**: When size/duration limits are reached
- **Error**: When recording initialization or saving fails

Example log output:

```
INFO recording saved {"path": "ssh/recordings/2025-10-24/alice-a1b2c3d4.cast", "size": 15234, "event_bytes": 14892}
WARN recording truncated {"reason": "max_size", "path": "ssh/recordings/2025-10-24/alice-a1b2c3d4.cast", "size": 10485920}
WARN periodic fsync failed {"temp_path": "/tmp/kadeessh-record-xyz.cast", "error": "..."}
ERROR recording upload failed; temp file preserved for manual recovery {"temp_path": "/tmp/kadeessh-record-xyz.cast", "storage_path": "...", "error": "storage unavailable"}
```

## Performance Considerations

- Events are streamed to a local temp file (`temp_dir`) as they arrive; memory use during a session is bounded to a small write buffer.
- The temp file is periodically fsynced (`flush_interval`), then uploaded to storage as one blob on session close and deleted. If the upload fails, the temp file is preserved and its path is logged.
- On server crash the temp file remains at its last fsynced state, so recordings can be recovered manually (up to the last `flush_interval`).
- Peak memory happens briefly at close, when the full recording is read from the temp file into memory to be handed to the storage backend.
- Set `max_size` to bound the recording. Setting `flush_interval` to a negative value disables periodic fsync but keeps everything else — use only if fsync latency is a concern and page-cache-only durability is acceptable.

## Crash recovery

If the process exits without running Close (SIGKILL, panic, host reboot), in-progress recordings remain in `temp_dir` under the pattern `kadeessh-record-<pid>-*.cast`. Each file is a self-contained cast v2 recording up to the last fsync boundary and can be played directly.

On the next startup, if `recover_orphans` is enabled (the default), any such files from previous PIDs are uploaded to storage automatically. Files whose header carries SSH metadata are filed at `ssh/recordings/<date>/<user>-<sid>-recovered.cast`; files without parseable headers land at `ssh/recordings/recovered/<original-tempfile-name>`. The temp file is removed only after a successful upload.
