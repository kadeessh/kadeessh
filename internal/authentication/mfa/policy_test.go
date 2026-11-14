package mfa

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestSealRoundTrip(t *testing.T) {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		t.Fatalf("random: %v", err)
	}
	plaintext := []byte("the moon is a lonely satellite")
	sb, err := Seal(key, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Ciphertext must be non-empty base64.
	if sb == "" {
		t.Fatal("sealed box is empty")
	}
	if _, err := base64.StdEncoding.DecodeString(string(sb)); err != nil {
		t.Fatalf("sealed box is not base64: %v", err)
	}
	got, err := sb.Open(key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestSealDetectsTampering(t *testing.T) {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		t.Fatalf("random: %v", err)
	}
	sb, err := Seal(key, []byte("orbit"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Flip a byte in the middle of the ciphertext (past the nonce +
	// enough into the box that we don't corrupt the length prefix
	// meaninglessly).
	raw, _ := base64.StdEncoding.DecodeString(string(sb))
	raw[30] ^= 0xff
	tampered := SealedBox(base64.StdEncoding.EncodeToString(raw))
	if _, err := tampered.Open(key); err == nil {
		t.Fatal("expected error on tampered ciphertext")
	}
}

func TestSealDetectsWrongKey(t *testing.T) {
	var k1, k2 [32]byte
	_, _ = io.ReadFull(rand.Reader, k1[:])
	_, _ = io.ReadFull(rand.Reader, k2[:])
	sb, _ := Seal(k1, []byte("data"))
	if _, err := sb.Open(k2); err == nil {
		t.Fatal("expected error on wrong-key open")
	}
}

func TestPolicyDefaults(t *testing.T) {
	var p Policy
	p.applyDefaults()

	if p.GracePeriod == 0 {
		t.Error("GracePeriod default not applied")
	}
	if p.SkSatisfiesMFA == nil || !*p.SkSatisfiesMFA {
		t.Error("SkSatisfiesMFA default should be true")
	}
	if p.MaxFailedAttempts != 5 {
		t.Errorf("MaxFailedAttempts default = %d, want 5", p.MaxFailedAttempts)
	}
	if time.Duration(p.LockoutDuration) != 30*time.Second {
		t.Errorf("LockoutDuration default = %s, want 30s", time.Duration(p.LockoutDuration))
	}
}

func TestPolicyExplicitZeroGrace(t *testing.T) {
	var p Policy
	if err := json.Unmarshal([]byte(`{"grace_period":"0s"}`), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	p.applyDefaults()
	if p.GracePeriod != 0 {
		t.Fatalf("GracePeriod = %s, want explicit zero", time.Duration(p.GracePeriod))
	}
	if got := p.EnforcementFor(nil, time.Now()); got != ModeRequire {
		t.Fatalf("EnforcementFor = %d, want ModeRequire", got)
	}
}

func TestPolicyEnforcementFor(t *testing.T) {
	var p Policy
	p.applyDefaults()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Enrolled user: always ModeRequire.
	enrolled := &EnrollmentRecord{Factors: map[string]json.RawMessage{"totp": json.RawMessage(`{}`)}}
	if got := p.EnforcementFor(enrolled, now); got != ModeRequire {
		t.Errorf("enrolled: got %d, want ModeRequire", got)
	}

	// Fresh user (nil record): ModeNudge (within grace).
	if got := p.EnforcementFor(nil, now); got != ModeNudge {
		t.Errorf("fresh: got %d, want ModeNudge", got)
	}

	// FirstSeenAt within grace: ModeNudge.
	within := &EnrollmentRecord{FirstSeenAt: now.Add(-24 * time.Hour)}
	if got := p.EnforcementFor(within, now); got != ModeNudge {
		t.Errorf("within grace: got %d, want ModeNudge", got)
	}

	// FirstSeenAt past grace: ModeRequire.
	past := &EnrollmentRecord{FirstSeenAt: now.Add(-31 * 24 * time.Hour)}
	if got := p.EnforcementFor(past, now); got != ModeRequire {
		t.Errorf("past grace: got %d, want ModeRequire", got)
	}

	// GracePeriod zero: always ModeRequire.
	p.GracePeriod = 0
	if got := p.EnforcementFor(&EnrollmentRecord{FirstSeenAt: now}, now); got != ModeRequire {
		t.Errorf("zero grace: got %d, want ModeRequire", got)
	}
}

func TestPolicyLockoutTransition(t *testing.T) {
	var p Policy
	p.applyDefaults()
	// Force small numbers for readability.
	p.MaxFailedAttempts = 3
	p.AttemptsWindow = caddy.Duration(1 * time.Minute)
	p.LockoutDuration = caddy.Duration(10 * time.Second)

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// First failure — starts a fresh window, count=1, no lock yet.
	state := p.NextLockoutState(FailedAttempts{}, now)
	if state.Count != 1 || !state.LockedUntil.IsZero() {
		t.Fatalf("after 1st failure = %+v", state)
	}
	if !state.WindowStart.Equal(now) {
		t.Errorf("WindowStart = %v, want %v", state.WindowStart, now)
	}

	// Second failure at t+30s within window.
	state = p.NextLockoutState(state, now.Add(30*time.Second))
	if state.Count != 2 || !state.LockedUntil.IsZero() {
		t.Fatalf("after 2nd failure = %+v", state)
	}

	// Third failure crosses the threshold: locked.
	state = p.NextLockoutState(state, now.Add(45*time.Second))
	if state.Count != 3 {
		t.Errorf("count = %d, want 3", state.Count)
	}
	wantLockUntil := now.Add(45 * time.Second).Add(10 * time.Second)
	if !state.LockedUntil.Equal(wantLockUntil) {
		t.Errorf("LockedUntil = %v, want %v", state.LockedUntil, wantLockUntil)
	}

	// A failure long after the window elapses resets the counter.
	state = p.NextLockoutState(state, now.Add(10*time.Minute))
	if state.Count != 1 {
		t.Errorf("count after window elapsed = %d, want 1", state.Count)
	}
}
