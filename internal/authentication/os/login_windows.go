//go:build windows
// +build windows

package osauth

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// The file is composed by combining bits and pieces from the repo:
// https://github.com/microsoft/hcsshim

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modadvapi32    = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW = modadvapi32.NewProc("LogonUserW")
)

// Logon types
const (
	LOGON32_LOGON_INTERACTIVE       uint32 = 2
	LOGON32_LOGON_NETWORK           uint32 = 3
	LOGON32_LOGON_BATCH             uint32 = 4
	LOGON32_LOGON_SERVICE           uint32 = 5
	LOGON32_LOGON_UNLOCK            uint32 = 7
	LOGON32_LOGON_NETWORK_CLEARTEXT uint32 = 8
	LOGON32_LOGON_NEW_CREDENTIALS   uint32 = 9
)

// Logon providers
const (
	LOGON32_PROVIDER_DEFAULT uint32 = 0
	LOGON32_PROVIDER_WINNT40 uint32 = 2
	LOGON32_PROVIDER_WINNT50 uint32 = 3
)

func logonUser(username *uint16, domain *uint16, password *uint16, logonType uint32, logonProvider uint32, token *windows.Token) (err error) {
	r1, _, e1 := syscall.Syscall6(procLogonUserW.Addr(), 6, uintptr(unsafe.Pointer(username)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(password)), uintptr(logonType), uintptr(logonProvider), uintptr(unsafe.Pointer(token)))
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// processToken returns a user token for the user specified by `user`. This should be in the form
// of either a DOMAIN\username or just username.
func processToken(user, password string) (windows.Token, error) {
	var (
		domain   string
		userName string
		token    windows.Token
	)

	split := strings.Split(user, "\\")
	if len(split) == 2 {
		domain = split[0]
		userName = split[1]
	} else if len(split) == 1 {
		userName = split[0]
	} else {
		return 0, fmt.Errorf("invalid user string `%s`", user)
	}

	if user == "" {
		return 0, errors.New("empty user string passed")
	}

	logonType := LOGON32_LOGON_INTERACTIVE
	// User asking to run as a local system account (NETWORK SERVICE, LOCAL SERVICE, SYSTEM)
	if domain == "NT AUTHORITY" {
		logonType = LOGON32_LOGON_SERVICE
	}

	if err := logonUser(
		windows.StringToUTF16Ptr(userName),
		windows.StringToUTF16Ptr(domain),
		windows.StringToUTF16Ptr(password),
		logonType,
		LOGON32_PROVIDER_DEFAULT,
		&token,
	); err != nil {
		return 0, errors.Wrap(err, "failed to logon user")
	}
	return token, nil
}

func openCurrentProcessToken() (windows.Token, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &token); err != nil {
		return 0, errors.Wrap(err, "failed to open current process token")
	}
	return token, nil
}
