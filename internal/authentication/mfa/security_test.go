package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	internalssh "github.com/kadeessh/kadeessh/internal/ssh"
	"go.uber.org/zap"
	gossh "golang.org/x/crypto/ssh"
)

type testOneTimeBlob struct {
	Used bool `json:"used"`
}

type testOneTimeFactor struct{}

func (testOneTimeFactor) Name() string   { return "one_time" }
func (testOneTimeFactor) Prompt() string { return "code: " }
func (testOneTimeFactor) Enroll(context.Context, string) (FactorBlob, EnrollmentArtifact, error) {
	return nil, EnrollmentArtifact{}, errors.New("not implemented")
}
func (testOneTimeFactor) NewBlob() FactorBlob { return &testOneTimeBlob{} }
func (testOneTimeFactor) Verify(_ context.Context, _ string, raw FactorBlob, response string) (bool, FactorBlob, error) {
	blob := raw.(*testOneTimeBlob)
	if response != "valid" || blob.Used {
		return false, nil, nil
	}
	return true, &testOneTimeBlob{Used: true}, nil
}

type testStore struct {
	mu        sync.Mutex
	rec       *EnrollmentRecord
	failStore bool
}

func (s *testStore) Load(context.Context, string, string) (*EnrollmentRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := cloneRecord(s.rec)
	return rec, rec != nil, nil
}

func (s *testStore) Update(_ context.Context, _, _ string, mutate func(*EnrollmentRecord) *EnrollmentRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	updated := mutate(cloneRecord(s.rec))
	if updated == nil {
		return nil
	}
	if s.failStore {
		return errors.New("store failed")
	}
	s.rec = cloneRecord(updated)
	return nil
}

func (*testStore) Delete(context.Context, string, string) error { return nil }
func (*testStore) List(context.Context, string) ([]string, error) {
	return nil, nil
}
func (*testStore) SealKey() [32]byte { return [32]byte{} }

func cloneRecord(rec *EnrollmentRecord) *EnrollmentRecord {
	if rec == nil {
		return nil
	}
	data, _ := json.Marshal(rec)
	var cloned EnrollmentRecord
	_ = json.Unmarshal(data, &cloned)
	return &cloned
}

func newVerificationConfig(store EnrollmentStore) *Config {
	return &Config{
		serverName:       "server",
		store:            store,
		factors:          map[string]SecondFactor{"one_time": testOneTimeFactor{}},
		VerifyPreference: []string{"one_time"},
	}
}

func TestVerifyAndCommitConsumesFactorAtomically(t *testing.T) {
	raw, err := json.Marshal(&testOneTimeBlob{})
	if err != nil {
		t.Fatal(err)
	}
	store := &testStore{rec: &EnrollmentRecord{
		Username: "alice",
		Factors:  map[string]json.RawMessage{"one_time": raw},
	}}
	config := newVerificationConfig(store)

	var accepted atomic.Int32
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			ok, _, err := config.verifyAndCommit(context.Background(), "alice", "valid")
			if err != nil {
				t.Errorf("verifyAndCommit: %v", err)
				return
			}
			if ok {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted %d concurrent uses, want 1", got)
	}
}

func TestVerifyAndCommitFailsClosedOnPersistenceError(t *testing.T) {
	raw, err := json.Marshal(&testOneTimeBlob{})
	if err != nil {
		t.Fatal(err)
	}
	store := &testStore{
		rec: &EnrollmentRecord{
			Username: "alice",
			Factors:  map[string]json.RawMessage{"one_time": raw},
		},
		failStore: true,
	}

	ok, _, err := newVerificationConfig(store).verifyAndCommit(context.Background(), "alice", "valid")
	if err == nil {
		t.Fatal("expected persistence error")
	}
	if ok {
		t.Fatal("verification succeeded despite persistence failure")
	}
}

func TestVerifyAndCommitRejectsEnrollmentReplacement(t *testing.T) {
	raw, err := json.Marshal(&testOneTimeBlob{Used: true})
	if err != nil {
		t.Fatal(err)
	}
	store := &testStore{rec: &EnrollmentRecord{
		Username: "alice",
		Factors:  map[string]json.RawMessage{"one_time": raw},
	}}

	ok, _, err := newVerificationConfig(store).verifyAndCommit(context.Background(), "alice", "valid")
	if err != nil {
		t.Fatalf("verifyAndCommit: %v", err)
	}
	if ok {
		t.Fatal("verification used stale factor state")
	}
}

func TestUsernameFromCtxUsesCanonicalIdentity(t *testing.T) {
	ctx := newTestSessionContext()
	SetAuthenticatedUsername(ctx, "canonical")
	if got := UsernameFromCtx(ctx); got != "canonical" {
		t.Fatalf("UsernameFromCtx = %q, want canonical", got)
	}
	if got := UsernameFromCtx(context.Background()); got != "" {
		t.Fatalf("UsernameFromCtx fallback = %q, want empty", got)
	}
}

func TestAllowsNoTouch(t *testing.T) {
	if !allowsNoTouch(nil, &gossh.Permissions{
		Extensions: map[string]string{"no-touch-required": ""},
	}) {
		t.Fatal("no-touch-required extension was not detected")
	}
	if allowsNoTouch(nil, &gossh.Permissions{}) {
		t.Fatal("ordinary permissions treated as no-touch")
	}
}

func TestSKTouchPolicy(t *testing.T) {
	policy := SKTouchPolicy{Enabled: true}
	event := AuthEvent{
		Flow:           FlowPublicKey,
		PrimaryKeyType: "sk-ssh-ed25519@openssh.com",
	}
	if !policy.SatisfiesMFA(event) {
		t.Fatal("touch-required security key did not satisfy MFA")
	}
	event.PrimaryKeyNoTouch = true
	if policy.SatisfiesMFA(event) {
		t.Fatal("no-touch security key satisfied MFA")
	}
	event.PrimaryKeyNoTouch = false
	event.Flow = FlowPassword
	if policy.SatisfiesMFA(event) {
		t.Fatal("security-key metadata bypassed a non-public-key flow")
	}
}

type testSessionContext struct {
	context.Context
	mu     sync.Mutex
	values map[any]any
}

func newTestSessionContext() *testSessionContext {
	return &testSessionContext{
		Context: context.Background(),
		values:  make(map[any]any),
	}
}

func (c *testSessionContext) Lock()   { c.mu.Lock() }
func (c *testSessionContext) Unlock() { c.mu.Unlock() }
func (c *testSessionContext) Value(key any) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if value, ok := c.values[key]; ok {
		return value
	}
	return c.Context.Value(key)
}
func (c *testSessionContext) SetValue(key, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[key] = value
}
func (*testSessionContext) User() string                          { return "requested-alias" }
func (*testSessionContext) SessionID() string                     { return "session" }
func (*testSessionContext) ClientVersion() string                 { return "client" }
func (*testSessionContext) ServerVersion() string                 { return "server" }
func (*testSessionContext) RemoteAddr() net.Addr                  { return testAddr("remote") }
func (*testSessionContext) LocalAddr() net.Addr                   { return testAddr("local") }
func (*testSessionContext) Permissions() *internalssh.Permissions { return nil }

type testConnMetadata struct{}

func (testConnMetadata) User() string          { return "requested-alias" }
func (testConnMetadata) SessionID() []byte     { return nil }
func (testConnMetadata) ClientVersion() []byte { return nil }
func (testConnMetadata) ServerVersion() []byte { return nil }
func (testConnMetadata) RemoteAddr() net.Addr  { return testAddr("remote") }
func (testConnMetadata) LocalAddr() net.Addr   { return testAddr("local") }

type testAddr string

func (a testAddr) Network() string { return "test" }
func (a testAddr) String() string  { return string(a) }

func TestGraceModeReturnsAuthenticationSuccess(t *testing.T) {
	store := &testStore{}
	config := &Config{
		Policy: Policy{
			GracePeriod:    24 * 60 * 60 * 1e9,
			gracePeriodSet: true,
		},
		serverName: "server",
		store:      store,
		log:        zap.NewNop(),
	}
	sctx := newTestSessionContext()
	SetAuthenticatedUsername(sctx, "canonical")
	perms := &gossh.Permissions{}

	got, err := config.continueAuthentication(sctx, testConnMetadata{}, perms, FlowPassword, nil)
	if err != nil {
		t.Fatalf("continueAuthentication returned auth error during grace: %v", err)
	}
	if got != perms {
		t.Fatal("continueAuthentication did not preserve primary permissions")
	}
	rec, ok, err := store.Load(context.Background(), "server", "canonical")
	if err != nil || !ok || rec.FirstSeenAt.IsZero() {
		t.Fatalf("FirstSeenAt not persisted: rec=%+v ok=%v err=%v", rec, ok, err)
	}
	if time.Since(rec.FirstSeenAt) > time.Minute {
		t.Fatalf("FirstSeenAt is stale: %v", rec.FirstSeenAt)
	}
}

func TestGraceModeFailsWhenFirstSeenCannotBePersisted(t *testing.T) {
	config := &Config{
		Policy: Policy{
			GracePeriod:    24 * 60 * 60 * 1e9,
			gracePeriodSet: true,
		},
		serverName: "server",
		store:      &testStore{failStore: true},
		log:        zap.NewNop(),
	}
	sctx := newTestSessionContext()
	SetAuthenticatedUsername(sctx, "canonical")

	if _, err := config.continueAuthentication(sctx, testConnMetadata{}, &gossh.Permissions{}, FlowPassword, nil); err == nil {
		t.Fatal("grace login succeeded when FirstSeenAt could not be persisted")
	}
}

func TestAuthenticatedContextTakesPrecedenceForActorStatus(t *testing.T) {
	pending := &EnrollmentRecord{FirstSeenAt: time.Now()}
	ctx := newTestSessionContext()
	setDecision(ctx, nil, FlowPassword, AuthDecision{Record: pending})
	markAuthenticated(ctx)

	if got := statusFromContext(ctx); got != StatusEnrolled {
		t.Fatalf("statusFromContext = %q, want %q", got, StatusEnrolled)
	}
}

func TestServiceReturnsPersistedPendingStateDuringGrace(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	service := newService(Policy{
		GracePeriod:    24 * 60 * 60 * 1e9,
		gracePeriodSet: true,
	}, &testStore{}, "server")
	service.now = func() time.Time { return now }

	decision, err := service.Decide(context.Background(), AuthEvent{
		Username: "alice",
		Flow:     FlowPassword,
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Action != ActionAllow || decision.Reason != ReasonGracePeriod {
		t.Fatalf("decision = %+v, want grace allow", decision)
	}
	if decision.Record == nil || !decision.Record.FirstSeenAt.Equal(now) {
		t.Fatalf("decision record = %+v, want persisted FirstSeenAt", decision.Record)
	}
}

func TestServiceRequiresVerificationForEnrolledUser(t *testing.T) {
	store := &testStore{rec: &EnrollmentRecord{
		Username: "alice",
		Factors:  map[string]json.RawMessage{"totp": json.RawMessage(`{}`)},
	}}
	service := newService(Policy{}, store, "server")

	decision, err := service.Decide(context.Background(), AuthEvent{
		Username: "alice",
		Flow:     FlowPassword,
	})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decision.Action != ActionVerify || decision.Reason != ReasonEnrolled {
		t.Fatalf("decision = %+v, want enrolled verification", decision)
	}
}

func TestServiceRejectsMissingCanonicalIdentity(t *testing.T) {
	service := newService(Policy{}, &testStore{}, "server")
	if _, err := service.Decide(context.Background(), AuthEvent{Flow: FlowPassword}); !errors.Is(err, errCanonicalUsername) {
		t.Fatalf("Decide error = %v, want canonical username error", err)
	}
}

func TestSessionStateCarriesDecisionAndAuthentication(t *testing.T) {
	ctx := newTestSessionContext()
	config := &Config{}
	record := &EnrollmentRecord{FirstSeenAt: time.Now()}

	SetAuthenticatedUsername(ctx, "alice")
	setDecision(ctx, config, FlowPassword, AuthDecision{
		Action: ActionAllow,
		Reason: ReasonGracePeriod,
		Mode:   ModeNudge,
		Record: record,
	})

	state := stateFromContext(ctx).snapshot()
	if state.username != "alice" || state.config != config || state.flow != FlowPassword {
		t.Fatalf("session state = %+v", state)
	}
	if state.decision.Record != record || state.authenticated {
		t.Fatalf("session decision state = %+v", state)
	}

	markAuthenticated(ctx)
	if !stateFromContext(ctx).snapshot().authenticated {
		t.Fatal("session state was not marked authenticated")
	}
}

func TestVerifyAndCommitRejectsConcurrentLockout(t *testing.T) {
	raw, err := json.Marshal(&testOneTimeBlob{})
	if err != nil {
		t.Fatal(err)
	}
	store := &testStore{rec: &EnrollmentRecord{
		Username: "alice",
		Factors:  map[string]json.RawMessage{"one_time": raw},
		FailedAttempts: FailedAttempts{
			LockedUntil: time.Now().Add(time.Minute),
		},
	}}
	config := newVerificationConfig(store)

	ok, _, err := config.verifyAndCommit(context.Background(), "alice", "valid")
	if err == nil {
		t.Fatal("expected lockout error")
	}
	if ok {
		t.Fatal("verification succeeded during lockout")
	}
}
