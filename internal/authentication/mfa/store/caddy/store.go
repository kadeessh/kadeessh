package caddystore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/kadeessh/kadeessh/internal/authentication/mfa"
)

const (
	rootPrefix  = "ssh/mfa"
	sealKeyPath = "ssh/mfa/seal.key"
	recordExt   = ".json"
)

func init() {
	caddy.RegisterModule(Store{})
}

// Store implements mfa.EnrollmentStore against a certmagic.Storage
// backend. Registered under ssh.authentication.mfa.stores.caddy.
type Store struct {
	// StorageRaw is an optional Caddy storage module. If nil, the
	// app-level context storage is used.
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`

	storage certmagic.Storage
	sealKey [32]byte
	locks   sync.Map
}

// CaddyModule identifies this module to Caddy.
func (Store) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ssh.authentication.mfa.stores.caddy",
		New: func() caddy.Module { return new(Store) },
	}
}

// Provision loads the storage backend and ensures a seal key exists.
func (s *Store) Provision(ctx caddy.Context) error {
	if s.StorageRaw != nil {
		val, err := ctx.LoadModule(s, "StorageRaw")
		if err != nil {
			return fmt.Errorf("loading storage module: %v", err)
		}
		st, err := val.(caddy.StorageConverter).CertMagicStorage()
		if err != nil {
			return fmt.Errorf("creating storage configuration: %v", err)
		}
		s.storage = st
	}
	if s.storage == nil {
		s.storage = ctx.Storage()
	}
	if err := s.loadOrGenerateSealKey(ctx); err != nil {
		return fmt.Errorf("mfa: initializing seal key: %w", err)
	}
	return nil
}

// SealKey returns the 32-byte seal key used to encrypt TOTP secrets.
func (s *Store) SealKey() [32]byte { return s.sealKey }

func (s *Store) loadOrGenerateSealKey(ctx context.Context) error {
	if s.storage.Exists(ctx, sealKeyPath) {
		raw, err := s.storage.Load(ctx, sealKeyPath)
		if err != nil {
			return err
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return fmt.Errorf("decoding seal key: %w", err)
		}
		if len(decoded) != 32 {
			return fmt.Errorf("seal key has wrong length: %d", len(decoded))
		}
		copy(s.sealKey[:], decoded)
		return nil
	}
	if _, err := io.ReadFull(rand.Reader, s.sealKey[:]); err != nil {
		return fmt.Errorf("generating seal key: %w", err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(s.sealKey[:]))
	return s.storage.Store(ctx, sealKeyPath, encoded)
}

func recordPath(server, username string) string {
	return path.Join(rootPrefix, server, username+recordExt)
}

func lockName(server, username string) string {
	return path.Join(rootPrefix, server, username+".lock")
}

// Load implements mfa.EnrollmentStore.
func (s *Store) Load(ctx context.Context, server, username string) (*mfa.EnrollmentRecord, bool, error) {
	if err := validateScope(server, username); err != nil {
		return nil, false, err
	}
	key := recordPath(server, username)
	if !s.storage.Exists(ctx, key) {
		return nil, false, nil
	}
	raw, err := s.storage.Load(ctx, key)
	if err != nil {
		return nil, false, err
	}
	var rec mfa.EnrollmentRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, false, fmt.Errorf("mfa: unmarshalling record for %q: %w", username, err)
	}
	if rec.Server != "" && rec.Server != server {
		return nil, false, fmt.Errorf("mfa: record server %q mismatches expected %q", rec.Server, server)
	}
	return &rec, true, nil
}

// Update implements mfa.EnrollmentStore. Serialized via the per-user
// shared-storage lock so concurrent writers on shared storage cannot
// clobber each other.
func (s *Store) Update(ctx context.Context, server, username string, mutate func(*mfa.EnrollmentRecord) *mfa.EnrollmentRecord) error {
	if err := validateScope(server, username); err != nil {
		return err
	}
	if mutate == nil {
		return errors.New("mfa: mutate func is required")
	}
	name := lockName(server, username)
	local := s.localLock(name)
	local.Lock()
	defer local.Unlock()
	if err := s.storage.Lock(ctx, name); err != nil {
		return fmt.Errorf("mfa: acquiring lock: %w", err)
	}
	defer func() { _ = s.storage.Unlock(ctx, name) }()

	rec, _, err := s.Load(ctx, server, username)
	if err != nil {
		return err
	}
	updated := mutate(rec)
	if updated == nil {
		return nil
	}
	updated.Server = server
	updated.Username = username
	if updated.Version == 0 {
		updated.Version = 1
	}
	data, err := json.Marshal(updated)
	if err != nil {
		return fmt.Errorf("mfa: marshaling record: %w", err)
	}
	return s.storage.Store(ctx, recordPath(server, username), data)
}

// Delete implements mfa.EnrollmentStore.
func (s *Store) Delete(ctx context.Context, server, username string) error {
	if err := validateScope(server, username); err != nil {
		return err
	}
	name := lockName(server, username)
	local := s.localLock(name)
	local.Lock()
	defer local.Unlock()
	if err := s.storage.Lock(ctx, name); err != nil {
		return fmt.Errorf("mfa: acquiring lock: %w", err)
	}
	defer func() { _ = s.storage.Unlock(ctx, name) }()

	key := recordPath(server, username)
	if !s.storage.Exists(ctx, key) {
		return nil
	}
	return s.storage.Delete(ctx, key)
}

// List implements mfa.EnrollmentStore.
func (s *Store) List(ctx context.Context, server string) ([]string, error) {
	if err := mfa.ValidateScopeComponent("server", server); err != nil {
		return nil, err
	}
	keys, err := s.storage.List(ctx, path.Join(rootPrefix, server), false)
	if err != nil {
		// Some backends return fs.ErrNotExist (or a wrapped variant)
		// when the directory is empty. Treat as an empty list.
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	users := make([]string, 0, len(keys))
	for _, k := range keys {
		base := path.Base(k)
		if !strings.HasSuffix(base, recordExt) {
			continue
		}
		users = append(users, strings.TrimSuffix(base, recordExt))
	}
	return users, nil
}

func validateScope(server, username string) error {
	if err := mfa.ValidateScopeComponent("server", server); err != nil {
		return err
	}
	return mfa.ValidateScopeComponent("username", username)
}

func (s *Store) localLock(name string) *sync.Mutex {
	lock, _ := s.locks.LoadOrStore(name, new(sync.Mutex))
	return lock.(*sync.Mutex)
}

var (
	_ caddy.Module        = (*Store)(nil)
	_ caddy.Provisioner   = (*Store)(nil)
	_ mfa.EnrollmentStore = (*Store)(nil)
)
