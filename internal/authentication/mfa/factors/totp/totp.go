// Package totp is a time-based one-time-password (RFC 6238) second
// factor for kadeessh's MFA. It is compatible with Google
// Authenticator, Authy, 1Password, and any RFC 6238 client that
// speaks the otpauth:// URI scheme.
package totp

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/kadeessh/kadeessh/internal/authentication/mfa"
	"github.com/mdp/qrterminal/v3"
	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"
)

func init() {
	caddy.RegisterModule(TOTP{})
}

// TOTP is the second-factor module. Register under
// ssh.authentication.mfa.factors.totp.
type TOTP struct {
	// Issuer is the label shown in authenticator apps. Defaults to
	// "Kadeessh".
	Issuer string `json:"issuer,omitempty"`

	// Digits is the number of digits in the code (6 or 8). Default 6.
	Digits int `json:"digits,omitempty"`

	// Period is the code refresh period in seconds. Default 30.
	Period uint `json:"period,omitempty"`

	// Algorithm is the HMAC algorithm ("SHA256" or "SHA512").
	// Default "SHA256". SHA1 is intentionally rejected.
	Algorithm string `json:"algorithm,omitempty"`

	// Skew is the number of ±periods accepted around the current one.
	// Default 1 (i.e. ±30s at Period=30).
	Skew uint `json:"skew,omitempty"`

	// SealKeyProvider is the store from which the TOTP factor reads
	// the seal key at Verify time. Populated at Provision by the
	// mfa.Config-provided context (see below).
	sealKey [32]byte
}

// CaddyModule identifies the module.
func (TOTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.mfa.factors.totp",
		New: func() caddy.Module { return new(TOTP) },
	}
}

// Provision applies defaults. The seal key is fetched lazily from the
// mfa.Config store on the first enrollment; we don't have access to
// the store at Provision time because module load order isn't
// guaranteed.
func (t *TOTP) Provision(ctx caddy.Context) error {
	if t.Issuer == "" {
		t.Issuer = "Kadeessh"
	}
	if t.Digits == 0 {
		t.Digits = 6
	}
	if t.Period == 0 {
		t.Period = 30
	}
	if t.Algorithm == "" {
		t.Algorithm = "SHA256"
	}
	if _, err := parseAlgo(t.Algorithm); err != nil {
		return err
	}
	if t.Skew == 0 {
		t.Skew = 1
	}
	return nil
}

// Name implements mfa.SecondFactor.
func (t *TOTP) Name() string { return "totp" }

// Prompt implements mfa.SecondFactor.
func (t *TOTP) Prompt() string {
	return fmt.Sprintf("%d-digit authenticator code: ", t.Digits)
}

// NewBlob implements the optional interface consumed by
// mfa.unmarshalBlob to decode the persisted TOTP payload.
func (*TOTP) NewBlob() mfa.FactorBlob { return &Blob{} }

// Blob is the persisted per-user TOTP payload. The secret is sealed
// (nacl/secretbox base64) with the store's seal key.
type Blob struct {
	Sealed              mfa.SealedBox `json:"sealed"`
	Digits              int           `json:"digits"`
	Period              uint          `json:"period"`
	Algorithm           string        `json:"algorithm"`
	Skew                uint          `json:"skew"`
	LastAcceptedCounter uint64        `json:"last_accepted_counter,omitempty"`
}

// SetSealKey injects the seal key so Enroll / Verify can seal/open
// the secret. Called by mfa.Config right after loading the factor.
func (t *TOTP) SetSealKey(k [32]byte) { t.sealKey = k }

// Enroll implements mfa.SecondFactor.
func (t *TOTP) Enroll(ctx context.Context, username string) (mfa.FactorBlob, mfa.EnrollmentArtifact, error) {
	if t.sealKey == ([32]byte{}) {
		return nil, mfa.EnrollmentArtifact{}, errors.New("totp: seal key not initialized")
	}
	algo, err := parseAlgo(t.Algorithm)
	if err != nil {
		return nil, mfa.EnrollmentArtifact{}, err
	}
	key, err := otptotp.Generate(otptotp.GenerateOpts{
		Issuer:      t.Issuer,
		AccountName: username,
		Digits:      digitsFor(t.Digits),
		Period:      t.Period,
		Algorithm:   algo,
	})
	if err != nil {
		return nil, mfa.EnrollmentArtifact{}, fmt.Errorf("totp: generating secret: %w", err)
	}

	sealed, err := mfa.Seal(t.sealKey, []byte(key.Secret()))
	if err != nil {
		return nil, mfa.EnrollmentArtifact{}, fmt.Errorf("totp: sealing secret: %w", err)
	}
	blob := &Blob{
		Sealed:    sealed,
		Digits:    t.Digits,
		Period:    t.Period,
		Algorithm: t.Algorithm,
		Skew:      t.Skew,
	}

	var qr bytes.Buffer
	qrterminal.GenerateWithConfig(key.URL(), qrterminal.Config{
		Level:     qrterminal.M,
		Writer:    &qr,
		BlackChar: qrterminal.BLACK,
		WhiteChar: qrterminal.WHITE,
		QuietZone: 1,
	})

	art := mfa.EnrollmentArtifact{
		Instructions: fmt.Sprintf(
			"Scan the QR code with your authenticator app, or add the URI/secret manually.\r\n"+
				"Algorithm: %s   Digits: %d   Period: %ds\r\n"+
				"Secret (base32): %s",
			strings.ToUpper(t.Algorithm), t.Digits, t.Period, key.Secret(),
		),
		OtpauthURI: key.URL(),
		QRCode:     qr.String(),
	}
	return blob, art, nil
}

// Verify implements mfa.SecondFactor.
func (t *TOTP) Verify(ctx context.Context, username string, raw mfa.FactorBlob, response string) (bool, mfa.FactorBlob, error) {
	if t.sealKey == ([32]byte{}) {
		return false, nil, errors.New("totp: seal key not initialized")
	}
	blob, err := coerceBlob(raw)
	if err != nil {
		return false, nil, err
	}
	if blob.Sealed == "" {
		return false, nil, errors.New("totp: blob has no sealed secret")
	}
	secretBytes, err := blob.Sealed.Open(t.sealKey)
	if err != nil {
		return false, nil, fmt.Errorf("totp: opening sealed secret: %w", err)
	}
	// Redact the plaintext secret from any log fields before it
	// leaves scope.
	defer zero(secretBytes)

	algo, err := parseAlgo(blob.Algorithm)
	if err != nil {
		return false, nil, err
	}
	code := strings.TrimSpace(response)
	if code == "" {
		return false, nil, nil
	}
	skew := blob.Skew
	if skew == 0 {
		skew = t.Skew
	}
	period := blob.Period
	if period == 0 {
		period = t.Period
	}
	nowCounter := uint64(time.Now().Unix()) / uint64(period)
	var matchedCounter uint64
	matched := 0
	for offset := -int64(skew); offset <= int64(skew); offset++ {
		counter := int64(nowCounter) + offset
		if counter < 0 {
			continue
		}
		candidate, err := otptotp.GenerateCodeCustom(
			string(secretBytes),
			time.Unix(counter*int64(period), 0),
			otptotp.ValidateOpts{
				Period:    period,
				Digits:    digitsFor(blob.Digits),
				Algorithm: algo,
			},
		)
		if err != nil {
			return false, nil, fmt.Errorf("totp: generating comparison code: %w", err)
		}
		equal := subtle.ConstantTimeCompare([]byte(code), []byte(candidate))
		if equal == 1 && matched == 0 {
			matchedCounter = uint64(counter)
		}
		matched |= equal
	}
	if matched == 0 || matchedCounter <= blob.LastAcceptedCounter {
		return false, nil, nil
	}
	updated := *blob
	updated.LastAcceptedCounter = matchedCounter
	return true, &updated, nil
}

// coerceBlob accepts either *Blob (fast path via NewBlob) or a
// generic map (fallback) and returns a *Blob.
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
		return nil, fmt.Errorf("totp: unexpected blob type %T", raw)
	}
}

func parseAlgo(s string) (otp.Algorithm, error) {
	switch strings.ToUpper(s) {
	case "SHA256":
		return otp.AlgorithmSHA256, nil
	case "SHA512":
		return otp.AlgorithmSHA512, nil
	default:
		return 0, fmt.Errorf("totp: unsupported or disallowed algorithm %q (SHA1 is not accepted)", s)
	}
}

func digitsFor(n int) otp.Digits {
	if n == 8 {
		return otp.DigitsEight
	}
	return otp.DigitsSix
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var (
	_ caddy.Module      = (*TOTP)(nil)
	_ caddy.Provisioner = (*TOTP)(nil)
	_ mfa.SecondFactor  = (*TOTP)(nil)
)
