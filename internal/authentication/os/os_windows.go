//go:build windows
// +build windows

package osauth

import (
	"errors"
	"os/user"

	"github.com/caddyserver/caddy/v2"
	"github.com/mohammed90/caddy-ssh/internal/authentication"

	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

// Gopher Slack resources:
// By Justen Walker (jwalk)
// https://gophers.slack.com/archives/C3G0G8HT4/p1629153276009700
// https://gophers.slack.com/archives/C3G0G8HT4/p1629153813012000
// https://gophers.slack.com/archives/C3G0G8HT4/p1629153929013200
// https://gophers.slack.com/archives/C3G0G8HT4/p1629154374016600
// https://gophers.slack.com/archives/C3G0G8HT4/p1629154475017500
// https://gophers.slack.com/archives/C3G0G8HT4/p1629154544018500
/**
possibly you could use one of:
LogonUserA function
LogonUserExA function
LogonUserExW function
LogonUserW function

However, I don't see the APIs in `golang.org/x/sys/windows` so you'll probably have to find a library that does it or write the syscalls yourself. If picking the latter option, you might want to check out the talk I gave last year at GopherCon: https://www.youtube.com/watch?v=EsPcKkESYPA since I walk through what you need to do (more or less). I have some code examples in this repo also: https://github.com/justenwalker/gophercon-2020-winapi (edited)

a quick Github search and I found an example that might get you there more quickly: https://github.com/akramchelong/CypressReport/blob/main/auth/loginhandler_windows.go#L128 - though I still recommend going in armed with the information to call windows syscalls and deal with unmanaged memory. (edited)

Justen Walker  1:52 AM
https://github.com/microsoft/hcsshim/blob/master/internal/winapi/logon.go using mkwinsyscall

and that one is straight from the proverbial horse's mouth. can't go wrong :smile: (edited)
and its usage: https://github.com/microsoft/hcsshim/blob/7fa8bda4e6ba503caf0d53d0a4ee99b9a64ceed8/internal/jobcontainers/logon.go#L41-L50
you'll probably want to set that `nil` to `windows.StringToUTF16Ptr(userPassword)`  but other than that, i think that's 90% of the work

Justen Walker  5:32 AM
@mohammedsahaf I added an example of the logon command [HERE](https://github.com/justenwalker/gophercon-2020-winapi/tree/main/logon). I had to play around with some of the parameters a bit, I think you may only be able to log into MicrosoftAccounts (using your Microsoft account password, if you linked your local account to your Microsoft Account) via LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50 . Local accounts seem to work with LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT
**/

func init() {
	caddy.RegisterModule(OS{})
}

const UserTokenKey string = "userTokenKey"

type OS struct {
	logger *zap.Logger
}

func (OS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.providers.password.os",
		New: func() caddy.Module { return new(OS) },
	}
}

func (pm *OS) Provision(ctx caddy.Context) error {
	pm.logger = ctx.Logger(pm)
	return nil
}

func (pm OS) AuthenticateUser(sshctx gossh.ConnMetadata, password []byte) (authentication.User, bool, error) {

	if len(password) == 0 {
		return nil, false, errors.New("password missing")
	}
	pm.logger.Info("auth begin", zap.String("username", sshctx.User()))

	user, err := user.Lookup(sshctx.User())
	if err != nil {
		return nil, false, err
	}

	tkn, err := processToken(user.Username, string(password))
	if err != nil {
		return nil, false, err
	}

	// defer tkn.Close()

	return account{
		user: user,
		permissions: &gossh.Permissions{
			CriticalOptions: map[string]string{
				"user": sshctx.User(),
			},
			Extensions: map[string]string{},
		},
		metadata: map[string]interface{}{
			UserTokenKey: tkn,
		},
	}, true, nil
}

var _ authentication.UserPasswordAuthenticator = (*OS)(nil)
