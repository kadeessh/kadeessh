package recovery

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// newFactor returns a Recovery module Provisioned with defaults but
// with dramatically reduced Argon2 parameters so tests stay fast.
func newFactor(t *testing.T) *Recovery {
	t.Helper()
	r := &Recovery{
		Count:         3,
		CodeLength:    8,
		Argon2Time:    1,
		Argon2Memory:  8 * 1024,
		Argon2Threads: 1,
	}
	if err := r.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	return r
}

func TestRecoveryEnrollProducesUniqueCodes(t *testing.T) {
	r := newFactor(t)
	_, art, err := r.Enroll(context.Background(), "alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if len(art.Codes) != 3 {
		t.Fatalf("wanted 3 codes, got %d", len(art.Codes))
	}
	seen := map[string]bool{}
	for _, c := range art.Codes {
		if c == "" {
			t.Error("empty code emitted")
		}
		if !strings.Contains(c, "-") {
			t.Errorf("code %q is not chunked", c)
		}
		if seen[c] {
			t.Errorf("duplicate code emitted: %q", c)
		}
		seen[c] = true
	}
}

func TestRecoveryVerifyRejectsWrongCode(t *testing.T) {
	r := newFactor(t)
	blob, _, err := r.Enroll(context.Background(), "alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	ok, _, err := r.Verify(context.Background(), "alice", blob, "not-a-real-code")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected verify to fail on wrong code")
	}
}

func TestRecoveryVerifyAcceptsThenRefusesSameCode(t *testing.T) {
	r := newFactor(t)
	blob, art, err := r.Enroll(context.Background(), "alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	code := art.Codes[0]

	// First use: accepted, updated blob returned.
	ok, updated, err := r.Verify(context.Background(), "alice", blob, code)
	if err != nil {
		t.Fatalf("verify 1: %v", err)
	}
	if !ok {
		t.Fatal("first use of code should be accepted")
	}
	if updated == nil {
		t.Fatal("expected updated blob on first use")
	}

	// Second use of the SAME code against the UPDATED blob: rejected.
	ok, _, err = r.Verify(context.Background(), "alice", updated, code)
	if err != nil {
		t.Fatalf("verify 2: %v", err)
	}
	if ok {
		t.Fatal("second use of the same code should be rejected")
	}

	// Different unused code still works.
	ok, _, err = r.Verify(context.Background(), "alice", updated, art.Codes[1])
	if err != nil {
		t.Fatalf("verify 3: %v", err)
	}
	if !ok {
		t.Fatal("second code should be usable")
	}
}

func TestRecoveryBlobRoundTripJSON(t *testing.T) {
	r := newFactor(t)
	blob, art, err := r.Enroll(context.Background(), "alice")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	data, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	loaded := r.NewBlob()
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// A code accepted before should still be accepted (once) against
	// the loaded blob.
	ok, _, err := r.Verify(context.Background(), "alice", loaded, art.Codes[2])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("code should verify after JSON round-trip")
	}
}
