//go:build windows && conpty
// +build windows,conpty

package pty

import (
	"fmt"
	"io"
	"os/exec"
	"syscall"

	"github.com/jeffreystoke/pty"
	"github.com/mohammed90/caddy-ssh/internal/authentication"
	osauth "github.com/mohammed90/caddy-ssh/internal/authentication/os"
	"github.com/mohammed90/caddy-ssh/internal/session"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

type caddyPty struct {
	pty pty.Pty
}

func (s Shell) openPty(sess session.Session, cmd []string) (sshPty, error) {
	ptyReq, winCh, isPty := sess.Pty()
	if s.ForcePTY && !isPty {
		return nil, fmt.Errorf("ssh: not pty")
	}
	s.logger.Info("openPty", zap.String("TERM", ptyReq.Term))
	args := []string{}
	if len(cmd) > 0 {
		args = append(args, "/C")
		args = append(args, cmd...)
	}

	shell := "cmd"
	if s.Shell != "" {
		shell = s.Shell
	}
	execCmd := exec.Command(shell, args...)

	env := make([]string, len(s.Env))
	for k, v := range s.Env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	execCmd.Env = append(execCmd.Env, sess.Environ()...)
	execCmd.Env = append(execCmd.Env, env...)
	execCmd.Env = append(execCmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))

	u, ok := sess.Context().Value(authentication.UserCtxKey).(authentication.User)
	if !ok {
		return nil, fmt.Errorf("pty: user context is absent")
	}

	var token windows.Token

	if metadata := u.Metadata(); metadata != nil {
		if tkn := metadata[osauth.UserTokenKey]; tkn != nil {
			switch t := tkn.(type) {
			case windows.Token:
				token = t
			case syscall.Token:
				token = windows.Token(t)
			}

		}
	}

	f, err := pty.StartWithAttrs(execCmd, &pty.Winsize{}, &syscall.SysProcAttr{
		HideWindow:    true,
		Token:         syscall.Token(token),
		CreationFlags: windows.CREATE_NEW_CONSOLE | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_PROTECTED_PROCESS,
	})
	if err != nil {
		return nil, err
	}
	spty := &caddyPty{f}
	go func() {
		for win := range winCh {
			spty.SetWindowsSize(win.Height, win.Width)
		}
	}()
	return spty, nil
}

func (p *caddyPty) Communicate(peer io.ReadWriter) {
	go func() {
		io.Copy(p.pty, peer) // stdin
	}()
	io.Copy(peer, p.pty) // stdout
}

func (p *caddyPty) SetWindowsSize(h, w int) {
	pty.Setsize(p.pty, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)}) //nolint
}

func (p *caddyPty) Close() error {
	return p.pty.Close()
}

var _ sshPty = (*caddyPty)(nil)
