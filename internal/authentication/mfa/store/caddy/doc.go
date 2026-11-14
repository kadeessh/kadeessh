// Package caddystore is the default MFA EnrollmentStore implementation.
// It persists records under a Caddy storage backend (whatever the app
// is configured with — filesystem, S3, Consul, etc.).
//
// Layout:
//
//	ssh/mfa/seal.key                       // 32 random bytes (base64)
//	ssh/mfa/<server>/<username>.json       // per-user enrollment record
//
// The per-user lock name passed to certmagic.Storage.Lock is
// "ssh/mfa/<server>/<username>.lock". It is a virtual name — no file
// with that path is written — but is reused verbatim in logs.
package caddystore

// The file is deliberately new; there was no prior implementation to
// preserve.
