//go:build !windows
// +build !windows

package pty

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
	"github.com/kadeessh/kadeessh/internal/session"
	"github.com/kadeessh/kadeessh/internal/ssh"
	"go.uber.org/zap"
)

type caddyPty struct {
	pty       *os.File
	sess      session.Session
	wantTTY   bool
	sessionId string

	logger *zap.Logger
}

func (s Shell) openPty(sess session.Session) (sshPty, error) {
	ptyReq, winCh, isPty := sess.Pty()
	if s.ForcePTY && !isPty {
		return nil, fmt.Errorf("ssh: not pty")
	}
	sessionId := sess.Context().Value(ssh.ContextKeySessionID).(string)
	s.logger.Info("start pty session",
		zap.String("term", ptyReq.Term),
		zap.String("session_id", sessionId),
		zap.String("remote_ip", sess.RemoteAddr().String()),
		zap.String("user", sess.User()),
		zap.String("command", sess.RawCommand()),
		zap.String("force_command", s.ForceCommand),
		zap.Bool("force_pty", s.ForcePTY),
		zap.Int("window_height", ptyReq.Window.Height),
		zap.Int("window_width", ptyReq.Window.Width),
	)

	args := []string{}
	wantTTY := len(sess.RawCommand()) > 0
	forcedCommand := s.ForceCommand != "" && s.ForceCommand != "none"
	if wantTTY || forcedCommand {
		args = append(args, "-c")
	}
	switch {
	case forcedCommand:
		args = append(args, s.ForceCommand)
	case wantTTY:
		args = append(args, sess.RawCommand())
	}

	user := s.pass.Get(sess.User())
	if user == nil {
		return nil, fmt.Errorf("error finding user details")
	}
	s.logger.Info("found user", zap.String("session_id", sessionId), zap.Object("user", user))

	shell := user.Shell
	execCmd := exec.Command(shell, args...)
	execCmd.Dir = user.HomeDir

	env := make([]string, len(s.Env))
	for k, v := range s.Env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	execCmd.Env = append(execCmd.Env, sess.Environ()...)
	execCmd.Env = append(execCmd.Env, env...)
	execCmd.Env = append(execCmd.Env, fmt.Sprintf("TERM=%s", ptyReq.Term))
	if forcedCommand && wantTTY {
		execCmd.Env = append(execCmd.Env, fmt.Sprintf("SSH_ORIGINAL_COMMAND=%s", sess.RawCommand()))
	}

	// hook std{in,out} to the session if the user is not requesting a shell, which is implied
	// by the absence of a command. Setting stderr by using sess.Stderr() causes the output of the commands
	// to disappear completely.
	// TODO: investigate whether the observation of setting stderr is a bug with `sess.Stderr()` or an expected behavior
	if wantTTY && !forcedCommand {
		execCmd.Stdin = sess
		execCmd.Stdout = sess
	}

	// thanks @mholt!
	// jailCommand(execCmd, u)
	// run as unprivileged user
	f, err := pty.StartWithAttrs(execCmd, &pty.Winsize{}, &syscall.SysProcAttr{
		Setsid: true,
		Credential: &syscall.Credential{
			Uid:         uint32(user.UID), // <-- other user's ID
			Gid:         uint32(user.GID),
			NoSetGroups: true,
		},
	})
	if err != nil {
		return nil, err
	}

	spty := &caddyPty{f, sess, wantTTY, sessionId, s.logger}
	go func() {
		for win := range winCh {
			spty.SetWindowsSize(win.Height, win.Width)
		}
	}()
	return spty, nil
}

// Communicate copies the IO across the PTY and the peer
func (p *caddyPty) Communicate(peer io.ReadWriter) {
	if !p.wantTTY {
		go func() {
			io.Copy(p.pty, peer) // stdin
		}()
	}
	io.Copy(peer, p.pty) // stdout
}

// SetWindowsSize updates the window size fo the PTY session
func (p *caddyPty) SetWindowsSize(h, w int) {
	pty.Setsize(p.pty, &pty.Winsize{Rows: uint16(h), Cols: uint16(w)}) //nolint
	p.logger.Info(
		"update window size",
		zap.String("session_id", p.sessionId),
		zap.Int("new_height", h),
		zap.Int("new_width", w),
	)
}

// Close closes the PTY session
func (p *caddyPty) Close() error {
	if err := p.pty.Close(); err != nil && err != io.EOF {
		return err
	}
	return nil
}

var _ sshPty = (*caddyPty)(nil)
