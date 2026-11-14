// Package recovery is a one-time recovery-code second factor for
// kadeessh's MFA. Codes are hashed with Argon2id and marked as used
// on first successful presentation, so replay is impossible.
package recovery

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/authentication/mfa"
	"golang.org/x/crypto/argon2"
)

func init() {
	caddy.RegisterModule(Recovery{})
}

// Recovery is the recovery-codes second-factor module. Registered as
// ssh.authentication.mfa.factors.recovery_codes.
type Recovery struct {
	// Count is the number of codes generated per enrollment.
	// Default 10.
	Count int `json:"count,omitempty"`

	// CodeLength is the byte length of each generated code before
	// base32 encoding. Default 10 (yields a 16-char base32 string).
	CodeLength int `json:"code_length,omitempty"`

	// Argon2Time / Memory / Threads tune the Argon2id parameters
	// used to hash the codes. Defaults chosen to match a
	// ~50ms verification on a 2020-era laptop CPU, appropriate
	// given that these are 80-bit codes with limited entropy that
	// benefit from moderate stretching.
	Argon2Time    uint32 `json:"argon2_time,omitempty"`
	Argon2Memory  uint32 `json:"argon2_memory,omitempty"`
	Argon2Threads uint8  `json:"argon2_threads,omitempty"`
}

// CaddyModule identifies the module.
func (Recovery) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.mfa.factors.recovery_codes",
		New: func() caddy.Module { return new(Recovery) },
	}
}

// Provision applies defaults.
func (r *Recovery) Provision(ctx caddy.Context) error {
	if r.Count == 0 {
		r.Count = 10
	}
	if r.CodeLength == 0 {
		r.CodeLength = 10
	}
	if r.Argon2Time == 0 {
		r.Argon2Time = 2
	}
	if r.Argon2Memory == 0 {
		r.Argon2Memory = 64 * 1024
	}
	if r.Argon2Threads == 0 {
		r.Argon2Threads = 4
	}
	return nil
}

// Name implements mfa.SecondFactor.
func (r *Recovery) Name() string { return "recovery_codes" }

// Prompt implements mfa.SecondFactor. Not usually shown alone — the
// verify prompt in mfa is combined with TOTP.
func (r *Recovery) Prompt() string {
	return "Recovery code (prefix with r-): "
}

// NewBlob returns a fresh *Blob for JSON decoding.
func (*Recovery) NewBlob() mfa.FactorBlob { return &Blob{} }

// Blob is the persisted recovery-codes payload. Each code entry
// contains an Argon2id hash of the code plus salt; the plaintext is
// discarded after the enrollment wizard finishes displaying it.
type Blob struct {
	Codes []CodeEntry `json:"codes"`
}

// CodeEntry is a single hashed recovery code.
type CodeEntry struct {
	// Salt is 16 random bytes, base64. Fresh per code.
	Salt string `json:"salt"`
	// Hash is the Argon2id hash, base64.
	Hash string `json:"hash"`
	// Params are the Argon2 parameters used to compute Hash. Stored
	// per-code so tuning changes don't invalidate existing codes.
	Params Argon2Params `json:"params"`
	// UsedAt is set when the code is consumed. Non-zero => single-use
	// exhausted.
	UsedAt time.Time `json:"used_at,omitempty"`
}

// Argon2Params captures the Argon2id parameters used to hash a code.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"keylen"`
}

// Enroll implements mfa.SecondFactor.
func (r *Recovery) Enroll(ctx context.Context, username string) (mfa.FactorBlob, mfa.EnrollmentArtifact, error) {
	plain := make([]string, r.Count)
	entries := make([]CodeEntry, r.Count)
	for i := 0; i < r.Count; i++ {
		code, err := generateCode(r.CodeLength)
		if err != nil {
			return nil, mfa.EnrollmentArtifact{}, err
		}
		plain[i] = code
		entry, err := r.hashCode(code)
		if err != nil {
			return nil, mfa.EnrollmentArtifact{}, err
		}
		entries[i] = entry
	}
	blob := &Blob{Codes: entries}
	art := mfa.EnrollmentArtifact{
		Codes:        plain,
		Instructions: "You will not see these codes again. Each code works exactly once, in place of your authenticator code, when prefixed with 'r-'.",
	}
	return blob, art, nil
}

// Verify implements mfa.SecondFactor. On success, the returned blob
// has UsedAt set on the matching code. The MFA orchestrator invokes
// verification and persists this blob in one locked store update.
func (r *Recovery) Verify(ctx context.Context, username string, raw mfa.FactorBlob, response string) (bool, mfa.FactorBlob, error) {
	blob, err := coerceBlob(raw)
	if err != nil {
		return false, nil, err
	}
	code := strings.TrimSpace(response)
	if code == "" {
		return false, nil, nil
	}
	// Iterate every code, hashing the response with each salt in
	// constant time (relative to which entry matches). Argon2id
	// itself is not constant-time relative to distinct salts, but
	// the loop structure prevents "did we get past entry N" leaks
	// via early return.
	matchIdx := -1
	for i, entry := range blob.Codes {
		if !entry.UsedAt.IsZero() {
			continue
		}
		saltBytes, err := b32NoPad.DecodeString(entry.Salt)
		if err != nil {
			// Malformed salt is a corruption bug; return an error so
			// the operator sees it.
			return false, nil, fmt.Errorf("recovery: decoding salt for entry %d: %w", i, err)
		}
		expected, err := b32NoPad.DecodeString(entry.Hash)
		if err != nil {
			return false, nil, fmt.Errorf("recovery: decoding hash for entry %d: %w", i, err)
		}
		hash := argon2.IDKey(
			[]byte(code), saltBytes,
			entry.Params.Time, entry.Params.Memory, entry.Params.Threads, entry.Params.KeyLen,
		)
		if subtle.ConstantTimeCompare(hash, expected) == 1 && matchIdx == -1 {
			matchIdx = i
		}
	}
	if matchIdx == -1 {
		return false, nil, nil
	}
	// Return an updated blob with the code marked used. The caller
	// merges this back into the record.
	updated := &Blob{Codes: append([]CodeEntry(nil), blob.Codes...)}
	updated.Codes[matchIdx].UsedAt = time.Now()
	return true, updated, nil
}

// hashCode produces a fresh CodeEntry from the plaintext code.
func (r *Recovery) hashCode(code string) (CodeEntry, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return CodeEntry{}, fmt.Errorf("recovery: generating salt: %w", err)
	}
	params := Argon2Params{
		Time:    r.Argon2Time,
		Memory:  r.Argon2Memory,
		Threads: r.Argon2Threads,
		KeyLen:  32,
	}
	hash := argon2.IDKey(
		[]byte(code), salt,
		params.Time, params.Memory, params.Threads, params.KeyLen,
	)
	return CodeEntry{
		Salt:   b32NoPad.EncodeToString(salt),
		Hash:   b32NoPad.EncodeToString(hash),
		Params: params,
	}, nil
}

// generateCode returns a base32-encoded random string of the
// requested byte length before encoding.
func generateCode(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("recovery: generating code: %w", err)
	}
	// Format like "abcd-efgh-ijkl-mnop" for readability. base32
	// (RFC 4648) is chosen over base64 so codes are case-insensitive
	// on the wire (users type them by hand).
	raw := strings.ToLower(b32NoPad.EncodeToString(buf))
	return chunk(raw, 4), nil
}

func chunk(s string, size int) string {
	if size <= 0 || len(s) <= size {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + len(s)/size)
	for i := 0; i < len(s); i += size {
		end := i + size
		if end > len(s) {
			end = len(s)
		}
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}

// b32NoPad is the standard base32 alphabet without padding, used for
// salts, hashes, and codes on disk / on the wire.
var b32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

func coerceBlob(raw mfa.FactorBlob) (*Blob, error) {
	switch v := raw.(type) {
	case *Blob:
		return v, nil
	case Blob:
		b := v
		return &b, nil
	case map[string]any:
		data, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		var b Blob
		if err := json.Unmarshal(data, &b); err != nil {
			return nil, err
		}
		return &b, nil
	default:
		return nil, errors.New("recovery: unexpected blob type")
	}
}

var (
	_ caddy.Module      = (*Recovery)(nil)
	_ caddy.Provisioner = (*Recovery)(nil)
	_ mfa.SecondFactor  = (*Recovery)(nil)
)
