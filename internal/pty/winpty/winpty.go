//go:build windows
// +build windows

package winpty

// source: https://github.com/cloudfoundry/diego-ssh/blob/master/winpty/winpty.go
import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	winpty                   *windows.DLL
	winpty_config_new        *windows.Proc
	winpty_config_free       *windows.Proc
	winpty_error_free        *windows.Proc
	winpty_error_msg         *windows.Proc
	winpty_open              *windows.Proc
	winpty_free              *windows.Proc
	winpty_conin_name        *windows.Proc
	winpty_conout_name       *windows.Proc
	winpty_spawn_config_new  *windows.Proc
	winpty_spawn_config_free *windows.Proc
	winpty_spawn             *windows.Proc
	winpty_set_size          *windows.Proc
)

var (
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	terminateProcess = kernel32.NewProc("TerminateProcess")
)

type WinPTY struct {
	StdIn  *os.File
	StdOut *os.File

	winPTYHandle uintptr
	childHandle  uintptr
}

const (
	WINPTY_SPAWN_FLAG_AUTO_SHUTDOWN = uint64(1)
)

func New(winPTYDLLDir string) (*WinPTY, error) {
	var err error
	winpty, err = windows.LoadDLL(filepath.Join(winPTYDLLDir, "winpty.dll"))
	if err != nil {
		return nil, err
	}
	winpty_config_new, err = winpty.FindProc("winpty_config_new")
	if err != nil {
		return nil, err
	}
	winpty_config_free, err = winpty.FindProc("winpty_config_free")
	if err != nil {
		return nil, err
	}
	winpty_error_free, err = winpty.FindProc("winpty_error_free")
	if err != nil {
		return nil, err
	}
	winpty_error_msg, err = winpty.FindProc("winpty_error_msg")
	if err != nil {
		return nil, err
	}
	winpty_open, err = winpty.FindProc("winpty_open")
	if err != nil {
		return nil, err
	}
	winpty_free, err = winpty.FindProc("winpty_free")
	if err != nil {
		return nil, err
	}
	winpty_conin_name, err = winpty.FindProc("winpty_conin_name")
	if err != nil {
		return nil, err
	}
	winpty_conout_name, err = winpty.FindProc("winpty_conout_name")
	if err != nil {
		return nil, err
	}
	winpty_spawn_config_new, err = winpty.FindProc("winpty_spawn_config_new")
	if err != nil {
		return nil, err
	}
	winpty_spawn_config_free, err = winpty.FindProc("winpty_spawn_config_free")
	if err != nil {
		return nil, err
	}
	winpty_spawn, err = winpty.FindProc("winpty_spawn")
	if err != nil {
		return nil, err
	}
	winpty_set_size, err = winpty.FindProc("winpty_set_size")
	if err != nil {
		return nil, err
	}

	var errorPtr uintptr
	defer winpty_error_free.Call(errorPtr)
	agentCfg, _, _ := winpty_config_new.Call(uintptr(0), uintptr(unsafe.Pointer(&errorPtr)))
	if agentCfg == 0 {
		return nil, fmt.Errorf("unable to create agent config: %s", winPTYErrorMessage(errorPtr))
	}

	winPTYHandle, _, _ := winpty_open.Call(agentCfg, uintptr(unsafe.Pointer(&errorPtr)))
	if winPTYHandle == 0 {
		return nil, fmt.Errorf("unable to launch WinPTY agent: %s", winPTYErrorMessage(errorPtr))
	}
	winpty_config_free.Call(agentCfg)

	return &WinPTY{
		winPTYHandle: winPTYHandle,
	}, nil
}

func (w *WinPTY) Open() error {
	if w.winPTYHandle == 0 {
		return errors.New("winpty dll not initialized")
	}

	stdinName, _, err := winpty_conin_name.Call(w.winPTYHandle)
	if stdinName == 0 {
		return fmt.Errorf("unable to get stdin pipe name: %s", err.Error())
	}

	stdoutName, _, err := winpty_conout_name.Call(w.winPTYHandle)
	if stdoutName == 0 {
		return fmt.Errorf("unable to get stdout pipe name: %s", err.Error())
	}

	stdinHandle, err := syscall.CreateFile((*uint16)(unsafe.Pointer(stdinName)), syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fmt.Errorf("unable to open stdin pipe: %s", err.Error())
	}

	stdoutHandle, err := syscall.CreateFile((*uint16)(unsafe.Pointer(stdoutName)), syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fmt.Errorf("unable to open stdout pipe: %s", err.Error())
	}

	w.StdIn = os.NewFile(uintptr(stdinHandle), "stdin")
	w.StdOut = os.NewFile(uintptr(stdoutHandle), "stdout")
	return nil
}

func (w *WinPTY) Run(cmd *exec.Cmd) error {
	escaped := makeCmdLine(append([]string{cmd.Path}, cmd.Args...))
	cmdLineStr, err := syscall.UTF16PtrFromString(escaped)
	if err != nil {
		w.StdOut.Close()
		return fmt.Errorf("failed to convert cmd (%s) to pointer: %s", escaped, err.Error())
	}

	env := ""
	for _, val := range cmd.Env {
		env += (val + "\x00")
	}

	var envPtr *uint16
	if env != "" {
		envPtr = &utf16.Encode([]rune(env))[0]
	}

	cwdStr, err := syscall.UTF16PtrFromString(cmd.Dir)
	if err != nil {
		return fmt.Errorf("Failed to convert working directory to pointer.")
	}

	var errorPtr uintptr
	defer winpty_error_free.Call(errorPtr)
	spawnCfg, _, _ := winpty_spawn_config_new.Call(
		uintptr(uint64(WINPTY_SPAWN_FLAG_AUTO_SHUTDOWN)),
		uintptr(0),
		uintptr(unsafe.Pointer(cmdLineStr)),
		uintptr(unsafe.Pointer(cwdStr)),
		uintptr(unsafe.Pointer(envPtr)),
		uintptr(unsafe.Pointer(&errorPtr)))
	if spawnCfg == 0 {
		w.StdOut.Close()
		return fmt.Errorf("unable to create process config: %s", winPTYErrorMessage(errorPtr))
	}

	var createProcessErr uint32
	spawnRet, _, err := winpty_spawn.Call(w.winPTYHandle,
		spawnCfg,
		uintptr(unsafe.Pointer(&w.childHandle)),
		uintptr(0),
		uintptr(unsafe.Pointer(&createProcessErr)),
		uintptr(unsafe.Pointer(&errorPtr)))
	winpty_spawn_config_free.Call(spawnCfg)
	if spawnRet == 0 {
		w.StdOut.Close()
		return fmt.Errorf("unable to spawn process: %s: %s", winPTYErrorMessage(errorPtr), windowsErrorMessage(createProcessErr))
	}

	return nil
}

func (w *WinPTY) Wait() error {
	_, err := syscall.WaitForSingleObject(syscall.Handle(w.childHandle), math.MaxUint32)
	if err != nil {
		return fmt.Errorf("unable to wait for child process: %s", err.Error())
	}

	var exitCode uint32
	err = syscall.GetExitCodeProcess(syscall.Handle(w.childHandle), &exitCode)
	if err != nil {
		return fmt.Errorf("couldn't get child exit code: %s", err.Error())
	}

	if exitCode != 0 {
		return &ExitError{WaitStatus: syscall.WaitStatus{ExitCode: exitCode}}
	}

	return nil
}

type ExitError struct {
	WaitStatus syscall.WaitStatus
}

func (ee *ExitError) Error() string {
	return fmt.Sprintf("exit code %d", ee.WaitStatus.ExitCode)
}

func (w *WinPTY) Close() {
	if w.winPTYHandle == 0 {
		return
	}

	winpty_free.Call(w.winPTYHandle)

	if w.StdIn != nil {
		w.StdIn.Close()
	}

	if w.StdOut != nil {
		w.StdOut.Close()
	}

	if w.childHandle != 0 {
		syscall.CloseHandle(syscall.Handle(w.childHandle))
	}
}

func (w *WinPTY) SetWinsize(columns, rows uint32) error {
	if columns == 0 || rows == 0 {
		return nil
	}
	ret, _, err := winpty_set_size.Call(w.winPTYHandle, uintptr(columns), uintptr(rows), uintptr(0))
	if ret == 0 {
		return fmt.Errorf("failed to set window size: %s", err.Error())
	}
	return nil
}

func (w *WinPTY) Signal(sig syscall.Signal) error {
	if sig == syscall.SIGINT {
		return w.sendCtrlC()
	} else if sig == syscall.SIGKILL {
		return w.terminateChild()
	}

	return syscall.Errno(syscall.EWINDOWS)
}

func (w *WinPTY) sendCtrlC() error {
	if w.childHandle == 0 {
		return nil
	}

	// 0x03 is Ctrl+C
	// this tells the agent to generate Ctrl+C in the child process
	// https://github.com/rprichard/winpty/blob/4978cf94b6ea48e38eea3146bd0d23210f87aa89/src/agent/ConsoleInput.cc#L387
	_, err := w.StdIn.Write([]byte{0x03})
	if err != nil {
		return fmt.Errorf("couldn't send ctrl+c to child: %s", err.Error())
	}
	return nil
}

func (w *WinPTY) terminateChild() error {
	if w.childHandle == 0 {
		return nil
	}
	ret, _, err := terminateProcess.Call(w.childHandle, 1)
	if ret == 0 {
		return fmt.Errorf("failed to terminate child process: %s", err.Error())
	}
	return nil
}

func winPTYErrorMessage(ptr uintptr) string {
	msgPtr, _, err := winpty_error_msg.Call(ptr)
	if msgPtr == 0 {
		return fmt.Sprintf("unknown error, couldn't convert: %s", err.Error())
	}

	out := make([]uint16, 0)
	p := unsafe.Pointer(msgPtr)

	for {
		val := *(*uint16)(p)
		if val == 0 {
			break
		}

		out = append(out, val)
		p = unsafe.Pointer(uintptr(p) + unsafe.Sizeof(uint16(0)))
	}
	return string(utf16.Decode(out))
}

func windowsErrorMessage(code uint32) string {
	flags := uint32(windows.FORMAT_MESSAGE_FROM_SYSTEM | windows.FORMAT_MESSAGE_IGNORE_INSERTS)
	langId := uint32(windows.SUBLANG_ENGLISH_US)<<10 | uint32(windows.LANG_ENGLISH)
	buf := make([]uint16, 512)

	_, err := windows.FormatMessage(flags, uintptr(0), code, langId, buf, nil)
	if err != nil {
		return fmt.Sprintf("0x%x", code)
	}
	return strings.TrimSpace(syscall.UTF16ToString(buf))
}

func makeCmdLine(args []string) string {
	if len(args) > 0 {
		args[0] = filepath.Clean(args[0])
		base := filepath.Base(args[0])
		match, _ := regexp.MatchString(`\.[a-zA-Z]{3}$`, base)
		if !match {
			args[0] += ".exe"
		}
	}
	var s string
	for _, v := range args {
		if s != "" {
			s += " "
		}
		s += syscall.EscapeArg(v)
	}

	return s
}
