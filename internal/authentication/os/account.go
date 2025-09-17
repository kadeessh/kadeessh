package osauth

import (
	user "github.com/tweekmonster/luser"

	"github.com/kadeessh/kadeessh/internal/authentication"
	gossh "golang.org/x/crypto/ssh"
)

type group struct {
	group *user.Group
}

// Gid returns the group ID as defined by the operating system
func (g group) Gid() string {
	return g.group.Gid
}

// Name returns the group name as defined in the operating system
func (g group) Name() string {
	return g.group.Name
}

type account struct {
	user        *user.User
	permissions *gossh.Permissions
	metadata    map[string]interface{}
}

func (a account) Uid() string {
	return a.user.Uid
}

func (a account) Gid() string {
	return a.user.Gid
}

func (a account) Username() string {
	return a.user.Username
}

func (a account) Name() string {
	return a.user.Name
}

func (a account) HomeDir() string {
	return a.user.HomeDir
}

func (a account) GroupIDs() ([]string, error) {
	return a.user.GroupIds()
}

func (a account) Groups() []authentication.Group {
	gs := []authentication.Group{}
	f, _ := a.GroupIDs()
	for _, v := range f {
		gr, _ := user.LookupGroupId(v)
		gs = append(gs, group{gr})
	}
	return gs
}

func (a account) Metadata() map[string]interface{} {
	return a.metadata
}

func (a account) Permissions() *gossh.Permissions {
	return a.permissions
}
