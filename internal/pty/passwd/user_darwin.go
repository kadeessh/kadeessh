//go:build darwin
// +build darwin

package passwd

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

const (
	usernameKey = "name"
	passwordKey = "password"
	gidKey      = "gid"
	infoKey     = "gecos"
	uidKey      = "uid"
	homeKey     = "dir"
	shellKey    = "shell"
)

func toUint(num string) uint {
	n, _ := strconv.ParseUint(num, 10, 64)
	return uint(n)
}

func fromShell(username string) (*Entry, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf(`set -euo pipefail; shopt -s extglob; dscacheutil -q user -a name %s`, username)) // nolint
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	if buf.Len() == 0 {
		return nil, fmt.Errorf("fromShell: invalid user: %+v", username)
	}

	// The format is as follows:
	//
	// name: _unknown
	// password: *
	// uid: 99
	// gid: 99
	// dir: /var/empty
	// shell: /usr/bin/false
	// gecos: Unknown User
	entry := &Entry{}
	for line, err := buf.ReadString('\n'); strings.TrimSpace(line) != "" && (err == nil || err != io.EOF); line, err = buf.ReadString('\n') {
		if err != nil && err != io.EOF {
			return nil, err
		}
		before, after, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			return nil, err
		}
		before = strings.TrimSpace(before)
		after = strings.TrimSpace(after)
		switch before {
		case usernameKey:
			entry.Username = strings.TrimSpace(after)
		case passwordKey:
			entry.Password = "*"
		case gidKey:
			entry.GID = toUint(after)
		case infoKey:
			entry.Info = strings.TrimSpace(after)
		case uidKey:
			entry.UID = toUint(after)
		case homeKey:
			entry.HomeDir = strings.TrimSpace(after)
		case shellKey:
			entry.Shell = strings.TrimSpace(after)
		default:
			// unrecognized, just skip it
			continue
		}
	}

	return entry, nil
}

func (p *passwd) Get(username string) *Entry {
	p.mu.Lock()
	if val, ok := p.cache[username]; ok {
		p.mu.Unlock()
		return val
	}
	p.mu.Unlock()

	entry, err := fromShell(username)
	if err != nil {
		return nil
	}

	p.mu.Lock()
	p.cache[username] = entry
	p.mu.Unlock()

	return entry
}
