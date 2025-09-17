//go:build !darwin && !windows
// +build !darwin,!windows

package passwd

import (
	"reflect"
	"runtime"
	"testing"
)

func getNobody() *Entry {
	e := &Entry{
		Username: "nobody",
		UID:      65534,
		GID:      65534,
		HomeDir:  "/nonexistent",
		Shell:    "/usr/sbin/nologin",
	}
	switch runtime.GOOS {
	case "linux":
		e.Password = "x"
		e.Info = "nobody"
	case "freebsd":
		e.Password = "*"
		e.Info = "Unprivileged user"
	default:
	}
	return e
}

func TestGet(t *testing.T) {
	type args struct {
		username string
	}
	tests := []struct {
		name string
		args args
		want *Entry
	}{
		{
			name: "successful",
			args: args{"nobody"},
			want: getNobody(),
		},
		{
			name: "user does not exist",
			args: args{`asdfasdf`},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := New().Get(tt.args.username)
			if !reflect.DeepEqual(entry, tt.want) {
				t.Errorf("Get() got = %+v, want %+v", entry, tt.want)
			}
		})
	}
}
