package authentication

import (
	"errors"
	"net"

	"github.com/mohammed90/caddy-ssh/internal/session"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	gossh "golang.org/x/crypto/ssh"
)

var invalidCredentials = errors.New("invalid credentials")

type ctxKey string

const (
	UserCtxKey ctxKey = "user"
)

// Comparer is a type that can securely compare
// a plaintext password with a hashed password
// in constant-time. Comparers should hash the
// plaintext password and then use constant-time
// comparison.
// As defined in github.com/caddyserver/caddy
type Comparer interface {
	// Compare returns true if the result of hashing
	// plaintextPassword with salt is hashedPassword,
	// false otherwise. An error is returned only if
	// there is a technical/configuration error.
	Compare(hashedPassword, plaintextPassword, salt []byte) (bool, error)
}

type Group interface {
	Gid() string
	Name() string
}

type User interface {
	Uid() string
	Gid() string
	Username() string
	Name() string
	HomeDir() string
	GroupIDs() ([]string, error)
	Groups() []Group
	Metadata() map[string]interface{}
	Permissions() *gossh.Permissions
}

type UserPasswordAuthenticator interface {
	AuthenticateUser(ctx session.ConnMetadata, password []byte) (User, bool, error)
}

type UserPublicKeyAuthenticator interface {
	AuthenticateUser(ctx session.ConnMetadata, key gossh.PublicKey) (User, bool, error)
}

// TODO: TBD -- the implementation should take into consideration: https://pkg.go.dev/golang.org/x/crypto/ssh#CertChecker
type UserCertificateAuthenticator interface {
	AuthenticateUser(ctx session.ConnMetadata, key gossh.PublicKey) (User, bool, error)
}

// TODO: TBD
type UserInteractiveAuthenticator interface {
	AuthenticateUser(conn session.ConnMetadata, client gossh.KeyboardInteractiveChallenge) (User, bool, error)
}

type authenticatorLogger struct {
	logger *zap.Logger
}

func (a authenticatorLogger) authStart(ctx session.ConnMetadata, providerCount int, remoteAddr net.Addr, fields ...zapcore.Field) {
	fields = append([]zapcore.Field{
		zap.Int("providers_count", providerCount),
		zap.String("remote_address", remoteAddr.String()),
		zap.String("username", ctx.User()),
	}, fields...)
	a.logger.Info(
		"authentication start",
		fields...,
	)
}

func (a authenticatorLogger) authFailed(ctx session.ConnMetadata, providerName string, fields ...zapcore.Field) {
	fields = append([]zapcore.Field{
		zap.String("provider", providerName),
		zap.String("username", ctx.User()),
	}, fields...)
	a.logger.Info(
		"authentication failed",
		fields...,
	)
}

func (a authenticatorLogger) authSuccessful(ctx session.ConnMetadata, providerName string, user User, fields ...zapcore.Field) {
	fields = append([]zapcore.Field{
		zap.String("provider", providerName),
		zap.String("user_id", user.Uid()),
		zap.String("username", user.Username()),
	}, fields...)
	a.logger.Info(
		"authentication successful",
		fields...,
	)
}

func (a authenticatorLogger) invalidCredentials(ctx session.ConnMetadata, fields ...zapcore.Field) {
	fields = append([]zapcore.Field{
		zap.String("username", ctx.User()),
	}, fields...)
	a.logger.Warn(
		"invalid credentials",
		fields...,
	)
}

func (a authenticatorLogger) authError(ctx session.ConnMetadata, providerName string, err error, fields ...zapcore.Field) {
	fields = append([]zapcore.Field{
		zap.Error(err),
		zap.String("provider", providerName),
		zap.String("usernames", ctx.User()),
	}, fields...)
	a.logger.Error(
		"authentication error",
		fields...,
	)
}
