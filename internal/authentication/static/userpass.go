package static

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/google/uuid"
	"github.com/kadeessh/kadeessh/internal/authentication"
	"github.com/kadeessh/kadeessh/internal/session"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Static{})
}

type Static struct {
	// The algorithm with which the passwords are hashed. Default: bcrypt
	HashRaw json.RawMessage `json:"hash,omitempty" caddy:"namespace=http.authentication.hashes inline_key=algorithm"`

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
func (Static) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.providers.password.static",
		New: func() caddy.Module { return new(Static) },
	}
}

// Provision of the Static authentication provider loads up the hasher, if defined or defaults to bcrypt, and validate
// process the user list (e,g. generate IDs if absent).
func (up *Static) Provision(ctx caddy.Context) error {
	up.logger = ctx.Logger(up)
	if up.HashRaw == nil {
		up.HashRaw = json.RawMessage(`{"algorithm": "bcrypt"}`)
	}
	// load password hasher
	hasherIface, err := ctx.LoadModule(up, "HashRaw")
	if err != nil {
		return fmt.Errorf("loading password hasher module: %v", err)
	}

	up.hash = hasherIface.(authentication.Comparer)
	if up.hash == nil {
		return fmt.Errorf("hash is required")
	}

	// load account list
	up.accounts = make(map[string]Account)
	for i, acct := range up.Accounts {
		if _, ok := up.accounts[acct.Username()]; ok {
			return fmt.Errorf("account %d: username is not unique: %s", i, acct.Username())
		}
		if acct.Username() == "" || acct.Password == "" {
			return fmt.Errorf("account %d: username and password are required", i)
		}

		if strings.TrimSpace(acct.ID) == "" {
			uid, err := uuid.NewUUID()
			if err != nil {
				return err
			}
			acct.ID = uid.String()
		}

		acct.password, err = base64.StdEncoding.DecodeString(acct.Password)
		if err != nil {
			return fmt.Errorf("base64-decoding password: %v", err)
		}
		if acct.Salt != "" {
			acct.salt, err = base64.StdEncoding.DecodeString(acct.Salt)
			if err != nil {
				return fmt.Errorf("base64-decoding salt: %v", err)
			}
		}
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

// AuthenticateUser in the Static authentication provider looks up the user in the in-memory map and checks for match in the password hash. If
// successful, the method returns the user account as an implementation of authentication.User and true; otherwise, the method returns empty account value,
// false, and an error.
func (up Static) AuthenticateUser(sshctx session.ConnMetadata, password []byte) (authentication.User, bool, error) {
	username := sshctx.User()
	if username == "" {
		return Account{}, false, errors.New("username missing")
	}

	account, accountExists := up.accounts[username]
	// don't return early if account does not exist; we want
	// to try to avoid side-channels that leak existence

	same, err := up.hash.Compare(account.password, password, account.salt)
	if err != nil {
		return Account{}, false, err
	}
	if !same || !accountExists {
		return Account{}, false, err
	}

	return account, true, nil
}

var (
	_ caddy.Provisioner                        = (*Static)(nil)
	_ authentication.UserPasswordAuthenticator = (*Static)(nil)
)
