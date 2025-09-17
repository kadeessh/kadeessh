package authorization

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/kadeessh/kadeessh/internal/session"
	"github.com/kadeessh/kadeessh/internal/ssh"
	"go.uber.org/zap"
)

type dummyContext struct {
	context context.Context
	ssh.Session
}

func (dc dummyContext) Context() context.Context {
	if dc.context == nil {
		dc.context = context.WithValue(context.Background(), ssh.ContextKeySessionID, "session-id")
	}
	return dc.context
}
func (dc dummyContext) User() string {
	return ""
}
func (dc dummyContext) RemoteAddr() net.Addr {
	return &net.IPAddr{}
}

type dummyAuthorizer struct {
	tag     string
	success bool
	err     error
	writer  io.Writer
}

func (da *dummyAuthorizer) Authorize(s session.Session) (DeauthorizeFunc, bool, error) {
	if da.err != nil {
		return nil, da.success, da.err
	}
	fmt.Fprintf(da.writer, "Auth: %s\n", da.tag)
	return func(session.Session) error {
		fmt.Fprintf(da.writer, "De-Auth: %s\n", da.tag)
		return nil
	}, da.success, da.err
}

func TestChainedAuthorize(t *testing.T) {
	outputBuffer := &bytes.Buffer{}
	type fields struct {
		authorizers []Authorizer
	}
	type args struct {
		sess session.Session
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "",
			fields: fields{
				authorizers: []Authorizer{
					&dummyAuthorizer{
						tag:     "A",
						success: true,
						writer:  outputBuffer,
					},
					&dummyAuthorizer{
						tag:     "B",
						success: true,
						writer:  outputBuffer,
					},
					&dummyAuthorizer{
						tag:     "C",
						success: true,
						writer:  outputBuffer,
					},
				},
			},
			args: args{
				sess: dummyContext{},
			},
			want: `Auth: A
Auth: B
Auth: C
`,
		},
		{
			name: "",
			fields: fields{
				authorizers: []Authorizer{
					&dummyAuthorizer{
						tag:     "A",
						success: true,
						writer:  outputBuffer,
					},
					&dummyAuthorizer{
						tag:     "B",
						success: false,
						writer:  outputBuffer,
					},
					&dummyAuthorizer{
						tag:     "C",
						success: true,
						writer:  outputBuffer,
					},
				},
			},
			args: args{
				sess: dummyContext{},
			},
			want: `Auth: A
Auth: B
De-Auth: B
De-Auth: A
`,
		},
		{
			name: "",
			fields: fields{
				authorizers: []Authorizer{
					&dummyAuthorizer{
						tag:     "A",
						success: false,
						err:     fmt.Errorf("error authorizing A"),
						writer:  outputBuffer,
					},
					&dummyAuthorizer{
						tag:     "B",
						success: true,
						writer:  outputBuffer,
					},
					&dummyAuthorizer{
						tag:     "C",
						success: true,
						writer:  outputBuffer,
					},
				},
			},
			args: args{
				sess: dummyContext{},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Chained{
				authorizers: tt.fields.authorizers,
				logger:      zap.NewNop(),
			}
			_, _, _ = c.Authorize(tt.args.sess)
			got := outputBuffer.String()
			if got != tt.want {
				t.Errorf("Chained.Authorize() got = %v, want %v", got, tt.want)
			}
			outputBuffer.Reset()
		})
	}
}
