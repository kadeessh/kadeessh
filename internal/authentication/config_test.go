package authentication

import "testing"

func TestSubjectAllowedNotDenied(t *testing.T) {
	type args struct {
		subject   string
		allowlist map[string]bool
		denylist  map[string]bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "subject passes if allowlist and denylist are empty",
			args: args{
				subject:   "subject-1",
				allowlist: map[string]bool{},
				denylist:  map[string]bool{},
			},
			want: true,
		},
		{
			name: "subject passes if they are not in the denylist",
			args: args{
				subject:   "subject-1",
				allowlist: map[string]bool{},
				denylist:  map[string]bool{"subject-2": true},
			},
			want: true,
		},
		{
			name: "subject passes if they are in the allowlist",
			args: args{
				subject:   "subject-1",
				allowlist: map[string]bool{"subject-1": true},
				denylist:  map[string]bool{},
			},
			want: true,
		},
		{
			name: "non-members of allowlist are not allowed if allowlist is not empty",
			args: args{
				subject:   "subject-2",
				allowlist: map[string]bool{"subject-1": true},
				denylist:  map[string]bool{},
			},
			want: false,
		},
		{
			name: "denylist takes precedence over allowlist",
			args: args{
				subject:   "subject-1",
				allowlist: map[string]bool{"subject-1": true},
				denylist:  map[string]bool{"subject-1": true},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := subjectAllowedNotDenied(tt.args.subject, tt.args.allowlist, tt.args.denylist); got != tt.want {
				t.Errorf("subjectAllowedNotDenied() = %v, want %v", got, tt.want)
			}
		})
	}
}
