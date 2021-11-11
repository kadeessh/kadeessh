package static

import (
	"runtime"

	"github.com/mohammed90/caddy-ssh/internal/authentication"
	gossh "golang.org/x/crypto/ssh"
)

type group struct {
	ID    string `json:"id,omitempty"`
	GName string `json:"name,omitempty"`
}

func (g group) Gid() string {
	return g.ID
}

func (g group) Name() string {
	return g.GName
}

// Account contains a username, password, and salt (if applicable).
type Account struct {
	ID string

	// A user's username.
	Uname string `json:"name"`

	// The user's hashed password, base64-encoded.
	Password string `json:"password"`

	// The user's password salt, base64-encoded; for
	// algorithms where external salt is needed.
	Salt string `json:"salt,omitempty"`

	Home   string                 `json:"home,omitempty"`
	Custom map[string]interface{} `json:"custom,omitempty"`

	permissions    *gossh.Permissions
	password, salt []byte
	gid            string
	groups         []group
}

func (a Account) Uid() string {
	return a.ID
}

func (a Account) Gid() string {
	return a.gid
}

func (a Account) Username() string {
	return a.Uname
}

func (a Account) Name() string {
	return a.Uname
}

func (a Account) HomeDir() string {
	if len(a.Home) > 0 {
		return a.Home
	}
	if runtime.GOOS == "windows" {
		return `C:\Users\Public`
	} else {
		return "/var/empty"
	}
}

func (a Account) GroupIDs() ([]string, error) {
	grps := []string{}
	for _, v := range a.groups {
		grps = append(grps, v.ID)
	}
	return grps, nil
}

func (a Account) Groups() []authentication.Group {
	gs := make([]authentication.Group, len(a.groups))
	for _, v := range a.groups {
		gs = append(gs, v)
	}
	return gs
}

func (a Account) Metadata() map[string]interface{} {
	return a.Custom
}

func (a Account) Permissions() *gossh.Permissions {
	return a.permissions
}
