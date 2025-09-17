//go:build !darwin && !windows
// +build !darwin,!windows

package passwd

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func parse(line string) (*Entry, error) {
	entryParts := strings.Split(line, ":")

	uid, err := strconv.Atoi(entryParts[2])
	if err != nil {
		return nil, err
	}
	uID := uint(uid) //nolint:gosec

	gid, err := strconv.Atoi(entryParts[3])
	if err != nil {
		return nil, err
	}
	gID := uint(gid) //nolint:gosec

	return &Entry{
		Username: entryParts[0],
		Password: entryParts[1],
		UID:      uID,
		GID:      gID,
		Info:     entryParts[4],
		HomeDir:  entryParts[5],
		Shell:    entryParts[6],
	}, nil
}

func (p *passwd) Get(username string) *Entry {
	if val, ok := p.cache[username]; ok {
		return val
	}

	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var entry *Entry
	for scanner.Scan() {
		line := scanner.Text()
		if uname, _, found := strings.Cut(line, ":"); uname != username || !found || (strings.Count(line, ":")+1) != 7 {
			continue
		}

		var err error
		entry, err = parse(line)
		if err != nil {
			return nil
		}
		if entry != nil {
			p.mu.Lock()
			p.cache[username] = entry
			p.mu.Unlock()
			return entry
		}
	}
	return entry
}
