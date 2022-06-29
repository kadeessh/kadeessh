//go:build windows
// +build windows

package passwd

import (
	"os/user"
	"strconv"
)

func (p *passwd) Get(username string) *Entry {
	if val, ok := p.cache[username]; ok {
		return val
	}

	u, err := user.Lookup(username)
	if err != nil {
		return nil
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	return &Entry{
		Username: username,
		UID:      uint(uid),
		GID:      uint(gid),
		HomeDir:  u.HomeDir,
	}
}
