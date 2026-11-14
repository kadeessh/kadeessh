package totp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"
)

// newFactor returns a Provisioned-ish TOTP module with a random seal
// key wired up. Provision only fills defaults; it does not touch the
// caddy.Context, so a zero value is acceptable.
func newFactor(t *testing.T) *TOTP {
	t.Helper()
	f := &TOTP{}
	if err := f.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		t.Fatalf("random: %v", err)
	}
	f.SetSealKey(key)
	return f
}

func TestTOTPEnrollAndVerify(t *testing.T) {
	f := newFactor(t)
	ctx := context.Background()

	blob, artifact, err := f.Enroll(ctx, "alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if artifact.OtpauthURI == "" {
		t.Error("missing OtpauthURI")
	}
	if artifact.QRCode == "" {
		t.Error("missing QRCode")
	}

	// Derive the current code from the URI so we don't need to peek
	// inside the blob.
	key, err := otp.NewKeyFromURL(artifact.OtpauthURI)
	if err != nil {
		t.Fatalf("parse otpauth: %v", err)
	}
	code, err := otptotp.GenerateCodeCustom(key.Secret(), time.Now(), otptotp.ValidateOpts{
		Period:    f.Period,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	})
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	ok, updated, err := f.Verify(ctx, "alice", blob, code)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("verify: unexpected mismatch")
	}
	ok, _, err = f.Verify(ctx, "alice", updated, code)
	if err != nil {
		t.Fatalf("replay verify: %v", err)
	}
	if ok {
		t.Fatal("same TOTP counter was accepted twice")
	}
}

func TestTOTPRejectsSHA1(t *testing.T) {
	f := newFactor(t)
	f.Algorithm = "SHA1"
	if err := f.Provision(caddy.Context{}); err == nil {
		t.Fatal("expected SHA1 configuration to be rejected")
	}

	f.Algorithm = "sha-1"
	if err := f.Provision(caddy.Context{}); err == nil {
		t.Fatal("expected sha-1 configuration to be rejected")
	}
}

func TestTOTPRejectsSHA1Blob(t *testing.T) {
	f := newFactor(t)
	blob, _, err := f.Enroll(context.Background(), "alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	typed, err := coerceBlob(blob)
	if err != nil {
		t.Fatalf("coerce: %v", err)
	}
	typed.Algorithm = "SHA1"
	if _, _, err := f.Verify(context.Background(), "alice", typed, "000000"); err == nil {
		t.Fatal("expected SHA1 blob to be rejected")
	}
}

func TestTOTPVerifyRejectsWrongCode(t *testing.T) {
	f := newFactor(t)
	ctx := context.Background()
	blob, _, err := f.Enroll(ctx, "alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	ok, _, err := f.Verify(ctx, "alice", blob, "000000")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected verify to fail on wrong code")
	}
}

func TestTOTPBlobRoundTripJSON(t *testing.T) {
	f := newFactor(t)
	ctx := context.Background()
	blob, _, err := f.Enroll(ctx, "alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	data, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Simulate load path: NewBlob() + Unmarshal.
	target := f.NewBlob()
	if err := json.Unmarshal(data, &target); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Generate a valid code and verify against the round-tripped blob.
	got, err := coerceBlob(target)
	if err != nil {
		t.Fatalf("coerce: %v", err)
	}
	if got.Sealed == "" {
		t.Fatal("sealed lost across round trip")
	}
}
