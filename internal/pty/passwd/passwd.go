package passwd

import (
	"sync"

	"go.uber.org/zap/zapcore"
)

type Entry struct {
	Username string
	Password string
	UID      uint
	GID      uint
	Info     string
	HomeDir  string
	Shell    string
}

// MarshalLogObject implements zapcore.ObjectMarshaler
func (e Entry) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("username", e.Username)
	// Linux, Darwin, Windows, and FreeBSD mask the password already
	enc.AddString("password", e.Password)
	enc.AddUint("uid", e.UID)
	enc.AddUint("gid", e.GID)
	enc.AddString("info", e.Info)
	enc.AddString("home_dir", e.HomeDir)
	enc.AddString("shell", e.Shell)
	return nil
}

type Passwd interface {
	Get(username string) *Entry
}

type passwd struct {
	mu    *sync.Mutex
	cache map[string]*Entry
}

func New() Passwd {
	return &passwd{
		mu:    &sync.Mutex{},
		cache: make(map[string]*Entry),
	}
}

var _ zapcore.ObjectMarshaler = Entry{}
