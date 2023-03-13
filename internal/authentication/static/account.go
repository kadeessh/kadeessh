package static

import (
	"runtime"

	"github.com/kadeessh/kadeessh/internal/authentication"
	gossh "golang.org/x/crypto/ssh"
)

type group struct {
	ID    string `json:"id,omitempty"`
	GName string `json:"name,omitempty"`
}

// Returns the group ID
func (g group) Gid() string {
	return g.ID
}

// Returns the group name
func (g group) Name() string {
	return g.GName
}

// Account contains a username, password, and salt (if applicable).
type Account struct {
	// The ID for the user to be identified with. If empty, UUID will be generated at provision-time.
	ID string `json:"id,omitempty"`

	// A user's username.
	Uname string `json:"name"`

	// The user's hashed password, base64-encoded.
	Password string `json:"password"`

	// The user's password salt, base64-encoded; for
	// algorithms where external salt is needed.
	Salt string `json:"salt,omitempty"`

	// The $HOME directory of the user. If empty, the app defaults to `C:\Users\Public` on Windows and `/var/empty` otherwise.
	Home string `json:"home,omitempty"`

	// Additional metadata for the user
	Custom map[string]interface{} `json:"custom,omitempty"`

	permissions    *gossh.Permissions
	password, salt []byte
	gid            string
	groups         []group
}

// returns the user ID, which is either provided in config or auto-generated at provision-time as UUIDv4
func (a Account) Uid() string {
	return a.ID
}

// returns the group ID, which is auto-generated at provision-time as UUIDv4
func (a Account) Gid() string {
	return a.gid
}

// returns the username as defined in the "name" JSON field
func (a Account) Username() string {
	return a.Uname
}

// returns the username as defined in the "name" JSON field
func (a Account) Name() string {
	return a.Uname
}

// HomeDir returns the custom $HOME if defined in the "home" JSON field, otherwise defaults to `C:\Users\Public` on Windows and `/var/empty` on *nix
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

// collects and returns the group IDs defiend for the user
func (a Account) GroupIDs() ([]string, error) {
	grps := []string{}
	for _, v := range a.groups {
		grps = append(grps, v.ID)
	}
	return grps, nil
}

// collects and returns the user groups as values implementing the authentication.Group interface
func (a Account) Groups() []authentication.Group {
	gs := make([]authentication.Group, len(a.groups))
	for i, v := range a.groups {
		gs[i] = v
	}
	return gs
}

// returns any custom metadata defined in the user record in the "custom" JSON field
func (a Account) Metadata() map[string]interface{} {
	return a.Custom
}

// returns the permission set of the user
func (a Account) Permissions() *gossh.Permissions {
	return a.permissions
}
