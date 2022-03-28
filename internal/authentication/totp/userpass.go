package totp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/google/uuid"
	"github.com/mohammed90/caddy-ssh/internal/authentication"
	"github.com/mohammed90/caddy-ssh/internal/session"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(TOTP{})
}

// The TOTP authentication provider relies on TOTP providers, e.g. Google Authenticator, as the password sources, so they
// are routinely rotated and only accessed by users having access to the app itself on a secured phone or platform.
type TOTP struct {
	// The token issuer to be displayed in the TOTP application
	Issuer string `json:"issuer,omitempty"`

	// The list of accounts to authenticate.
	Accounts []Account `json:"accounts,omitempty"`

	accounts map[string]Account      `json:"-"`
	hash     authentication.Comparer `json:"-"`

	logger *zap.Logger
}

// This method indicates that the type is a Caddy
// module. The returned ModuleInfo must have both
// a name and a constructor function. This method
// must not have any side-effects.
func (TOTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.providers.password.totp",
		New: func() caddy.Module { return new(TOTP) },
	}
}

// Provision loads up the users defined in the config, set up the totp keys, and generate the {user,group} IDs if necessary.
func (up *TOTP) Provision(ctx caddy.Context) error {
	up.logger = ctx.Logger(up)

	// load account list
	up.accounts = make(map[string]Account)
	for i, acct := range up.Accounts {
		if _, ok := up.accounts[acct.Username()]; ok {
			return fmt.Errorf("account %d: username is not unique: %s", i, acct.Username())
		}
		if acct.Username() == "" || len(acct.Secret) == 0 {
			return fmt.Errorf("account %d: username and password are required", i)
		}

		if strings.TrimSpace(acct.ID) == "" {
			uid, err := uuid.NewUUID()
			if err != nil {
				return err
			}
			acct.ID = uid.String()
		}

		secretBytes, err := base64.StdEncoding.DecodeString(acct.Secret)
		if err != nil {
			return fmt.Errorf("base64-decoding password: %v", err)
		}
		acct.secret = bytes.TrimSpace(secretBytes)
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      up.Issuer,
			AccountName: acct.Uname,
			Secret:      acct.secret,
			SecretSize:  uint(len(acct.secret)),
		})
		if err != nil {
			return err
		}
		acct.otpKey = key

		gid, err := uuid.NewUUID()
		if err != nil {
			return err
		}
		acct.gid = gid.String()
		// Every user belongs to at least a group of their own name
		acct.groups = append(acct.groups, group{
			ID:    gid.String(),
			GName: acct.Username(),
		})
		up.accounts[acct.Username()] = acct
	}
	up.Accounts = nil // allow GC to deallocate
	return nil
}

// AuthenticateUser will validate the provided TOTP against the currently valid one
func (up TOTP) AuthenticateUser(sshctx session.ConnMetadata, password []byte) (authentication.User, bool, error) {
	username := sshctx.User()
	if username == "" {
		return Account{}, false, errors.New("username missing")
	}

	account, accountExists := up.accounts[username]

	// don't return early if account does not exist; we want
	// to try to avoid side-channels that leak existence
	if !totp.Validate(string(password), account.otpKey.Secret()) || !accountExists {
		return Account{}, false, errors.New("invalid password")
	}
	return account, true, nil
}

var (
	_ caddy.Provisioner                        = (*TOTP)(nil)
	_ authentication.UserPasswordAuthenticator = (*TOTP)(nil)
)
