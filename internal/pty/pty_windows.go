//go:build windows && !conpty
// +build windows,!conpty

package pty

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/mohammed90/caddy-ssh/internal/authentication"
	osauth "github.com/mohammed90/caddy-ssh/internal/authentication/os"
	"github.com/mohammed90/caddy-ssh/internal/pty/winpty"
	"github.com/mohammed90/caddy-ssh/internal/session"
	"golang.org/x/sys/windows"
)

type caddyPty struct {
	pty   *winpty.WinPTY
	token windows.Token
}

func (s Shell) openPty(sess session.Session, cmd []string) (sshPty, error) {
	ptyReq, winCh, isPty := sess.Pty()
	if s.ForcePTY && !isPty {
		return nil, fmt.Errorf("ssh: not pty")
	}

	args := []string{}
	if len(cmd) > 0 {
		args = append(args, "/C")
		args = append(args, cmd[1:]...)
	}

	shell := "cmd"
	if s.Shell != "" {
		shell = s.Shell
	}
	//  execCmd := exec.CommandContext(sess.Context(), shell, args...)

	var env []string
	for k, v := range s.Env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	// execCmd.Env = append(execCmd.Env, env...)

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

	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("Failed to get dir on setup: %s", err)
	}

	execCmd := &exec.Cmd{
		Path: shell,
		Args: args,
		Env:  env,
		Dir:  u.HomeDir(),
		SysProcAttr: &syscall.SysProcAttr{
			HideWindow:    true,
			Token:         syscall.Token(token),
			CreationFlags: windows.CREATE_NEW_CONSOLE | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_BREAKAWAY_FROM_JOB | windows.CREATE_PROTECTED_PROCESS,
		},
	}

	wpty, err := winpty.New(wd)
	if err != nil {
		return nil, err
	}
	if err := wpty.SetWinsize(uint32(ptyReq.Window.Width), uint32(ptyReq.Window.Height)); err != nil {
		return nil, err
	}

	if err = wpty.Open(); err != nil {
		return nil, err
	}
	if err := wpty.Run(execCmd); err != nil {
		return nil, err
	}

	spty := &caddyPty{wpty, token}
	go func() {
		for win := range winCh {
			spty.SetWindowsSize(win.Width, win.Height)
		}
	}()
	return spty, nil
}

func (p *caddyPty) Communicate(peer io.ReadWriter) {
	go func() {
		io.Copy(p.pty.StdIn, peer) // stdin
	}()
	io.Copy(peer, p.pty.StdOut) // stdout
}

func (p *caddyPty) SetWindowsSize(w, h int) {
	p.pty.SetWinsize(uint32(w), uint32(h))
}

func (p *caddyPty) Close() error {
	p.pty.Close()
	if p.token != 0 {
		p.token.Close()
	}
	return nil
}

var _ sshPty = (*caddyPty)(nil)
