// Package hashes registers password-hash comparer modules under the
// ssh.authentication.hashes namespace consumed by the static password
// provider.
//
// This package exists so the shipped kadeessh binary can validate
// bcrypt-hashed passwords out of the box without users having to build
// a custom binary that includes caddy's HTTP-flavoured caddyauth
// module. New hashers (scrypt, argon2, ...) belong here.
package hashes

import (
	"github.com/caddyserver/caddy/v2"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	caddy.RegisterModule(Bcrypt{})
}

// Bcrypt implements authentication.Comparer using the bcrypt password
// hashing algorithm.
type Bcrypt struct{}

// CaddyModule identifies this module to Caddy.
func (Bcrypt) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.hashes.bcrypt",
		New: func() caddy.Module { return new(Bcrypt) },
	}
}

// Compare implements authentication.Comparer. The salt argument is
// ignored: bcrypt embeds its own per-hash salt in the hash string.
func (Bcrypt) Compare(hashedPassword, plaintextPassword, _ []byte) (bool, error) {
	err := bcrypt.CompareHashAndPassword(hashedPassword, plaintextPassword)
	if err == nil {
		return true, nil
	}
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	return false, err
}
