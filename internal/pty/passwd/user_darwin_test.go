//go:build darwin
// +build darwin

package passwd

import (
	"os"
	"reflect"
	"testing"
)

func Test_fromShell(t *testing.T) {
	type args struct {
		username string
	}
	type tc struct {
		name    string
		args    args
		want    *Entry
		wantErr bool
	}
	tests := []tc{
		{
			name:    "username contains double-quote",
			args:    args{`sadf"dafds`},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "username contains single-quote",
			args:    args{`sadf'dafds`},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "username contains env var",
			args:    args{`$HOME`},
			want:    nil,
			wantErr: true,
		},
	}
	// ref: https://docs.github.com/en/actions/learn-github-actions/environment-variables#default-environment-variables
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		tests = append(tests, tc{
			// GitHub Actions specific values
			name: "successful",
			args: args{"runner"},
			want: &Entry{
				Username: "runner",
				Password: "*",
				UID:      501,
				GID:      20,
				Info:     "runner",
				HomeDir:  "/Users/runner",
				Shell:    "/bin/bash",
			},
			wantErr: false,
		})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := fromShell(tt.args.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("fromShell() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(entry, tt.want) {
				t.Errorf("fromShell() Entry = %v, want %v", entry, tt.want)
			}
		})
	}
}
