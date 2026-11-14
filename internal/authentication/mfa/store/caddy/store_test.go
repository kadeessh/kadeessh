package caddystore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/kadeessh/kadeessh/internal/authentication/mfa"
)

// testTime is a deterministic timestamp so equality comparisons are
// stable across runs.
var testTime = time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)

// newTestStore returns a Store backed by a caddy.FileStorage rooted
// in t.TempDir, with a fresh seal key.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s := &Store{
		storage: &certmagic.FileStorage{Path: dir},
	}
	// loadOrGenerateSealKey uses only context.Context and the
	// storage handle, so a real caddy.Context isn't required.
	if err := s.loadOrGenerateSealKey(context.Background()); err != nil {
		t.Fatalf("seal key: %v", err)
	}
	return s
}

func TestStoreLoadReturnsNothingForMissing(t *testing.T) {
	s := newTestStore(t)
	rec, ok, err := s.Load(context.Background(), "srv0", "ghost")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if ok || rec != nil {
		t.Fatalf("expected no record, got %+v (ok=%v)", rec, ok)
	}
}

func TestStoreRejectsUnsafeScope(t *testing.T) {
	s := newTestStore(t)
	for _, tc := range []struct {
		server string
		user   string
	}{
		{server: "../other", user: "alice"},
		{server: "srv0", user: "../../seal"},
		{server: "srv0", user: `domain\alice`},
	} {
		if err := s.Update(context.Background(), tc.server, tc.user, func(*mfa.EnrollmentRecord) *mfa.EnrollmentRecord {
			return &mfa.EnrollmentRecord{}
		}); err == nil {
			t.Fatalf("Update(%q, %q) accepted unsafe scope", tc.server, tc.user)
		}
	}
}

func TestStoreUpdatePersists(t *testing.T) {
	s := newTestStore(t)
	err := s.Update(context.Background(), "srv0", "alice", func(cur *mfa.EnrollmentRecord) *mfa.EnrollmentRecord {
		if cur == nil {
			cur = &mfa.EnrollmentRecord{}
		}
		cur.EnrolledAt = testTime
		return cur
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	rec, ok, err := s.Load(context.Background(), "srv0", "alice")
	if err != nil || !ok {
		t.Fatalf("load after update: err=%v ok=%v", err, ok)
	}
	if !rec.EnrolledAt.Equal(testTime) {
		t.Fatalf("EnrolledAt = %v, want %v", rec.EnrolledAt, testTime)
	}
	if rec.Username != "alice" || rec.Server != "srv0" {
		t.Errorf("scope fields = %q/%q, want srv0/alice", rec.Server, rec.Username)
	}
}

func TestStoreUpdateNilReturnLeavesRecord(t *testing.T) {
	s := newTestStore(t)
	// Seed a record.
	_ = s.Update(context.Background(), "srv0", "alice", func(cur *mfa.EnrollmentRecord) *mfa.EnrollmentRecord {
		return &mfa.EnrollmentRecord{EnrolledAt: testTime}
	})
	// A nil return should be a no-op.
	err := s.Update(context.Background(), "srv0", "alice", func(cur *mfa.EnrollmentRecord) *mfa.EnrollmentRecord {
		return nil
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	rec, ok, err := s.Load(context.Background(), "srv0", "alice")
	if err != nil || !ok {
		t.Fatalf("load: err=%v ok=%v", err, ok)
	}
	if !rec.EnrolledAt.Equal(testTime) {
		t.Error("record was clobbered by nil-return mutate")
	}
}

// TestStoreUpdateConcurrentIncrement fires many parallel Updates
// against the same key. If Update didn't serialise via
// certmagic.Storage.Lock, the final counter would be less than N
// (lost updates) — this test verifies it lands at exactly N.
func TestStoreUpdateConcurrentIncrement(t *testing.T) {
	s := newTestStore(t)

	const N = 50
	var wg sync.WaitGroup
	var errs atomic.Int64
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			err := s.Update(context.Background(), "srv0", "alice", func(cur *mfa.EnrollmentRecord) *mfa.EnrollmentRecord {
				if cur == nil {
					cur = &mfa.EnrollmentRecord{}
				}
				cur.FailedAttempts.Count++
				return cur
			})
			if err != nil {
				errs.Add(1)
				t.Errorf("update: %v", err)
			}
		}()
	}
	wg.Wait()
	if errs.Load() != 0 {
		t.Fatalf("%d Update calls failed", errs.Load())
	}

	rec, ok, err := s.Load(context.Background(), "srv0", "alice")
	if err != nil || !ok {
		t.Fatalf("load: err=%v ok=%v", err, ok)
	}
	if rec.FailedAttempts.Count != N {
		t.Fatalf("Count = %d, want %d (lost updates!)", rec.FailedAttempts.Count, N)
	}
}

// TestStoreListEmptyDir verifies List returns no error and an empty
// slice when the server directory does not exist yet.
func TestStoreListEmptyDir(t *testing.T) {
	s := newTestStore(t)
	users, err := s.List(context.Background(), "empty")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected empty list, got %v", users)
	}
}

func TestStoreListReturnsUsers(t *testing.T) {
	s := newTestStore(t)
	for _, u := range []string{"alice", "bob"} {
		user := u
		if err := s.Update(context.Background(), "srv0", user, func(*mfa.EnrollmentRecord) *mfa.EnrollmentRecord {
			return &mfa.EnrollmentRecord{}
		}); err != nil {
			t.Fatalf("seed %s: %v", user, err)
		}
	}
	users, err := s.List(context.Background(), "srv0")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !equalSet(users, []string{"alice", "bob"}) {
		t.Errorf("List = %v, want [alice bob]", users)
	}
}

func TestStoreDelete(t *testing.T) {
	s := newTestStore(t)
	if err := s.Update(context.Background(), "srv0", "alice", func(*mfa.EnrollmentRecord) *mfa.EnrollmentRecord {
		return &mfa.EnrollmentRecord{}
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.Delete(context.Background(), "srv0", "alice"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, ok, err := s.Load(context.Background(), "srv0", "alice")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if ok {
		t.Error("record still exists after delete")
	}
	// Deleting a missing record is a no-op.
	if err := s.Delete(context.Background(), "srv0", "ghost"); err != nil {
		t.Errorf("delete missing: %v", err)
	}
}

func equalSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	m := make(map[string]bool, len(want))
	for _, s := range want {
		m[s] = true
	}
	for _, s := range got {
		if !m[s] {
			return false
		}
	}
	return true
}
