package store

import (
	"errors"
	"fmt"
	"sync"
)

// ErrSecretNotPersisted means the value is usable for this session but the
// system credential store refused to keep it. Callers must surface that to the
// user instead of reporting a successful save: the secret will be gone after a
// restart.
var ErrSecretNotPersisted = errors.New("secret is kept in memory only")

// SessionSecrets keeps writes in memory first, so a temporarily unavailable
// keyring cannot resurrect an older password. It never creates a plaintext file.
type SessionSecrets struct {
	mu      sync.Mutex
	primary SecretStore
	values  map[string]string
	deleted map[string]bool
}

func NewSessionSecrets(primary SecretStore) *SessionSecrets {
	return &SessionSecrets{primary: primary, values: map[string]string{}, deleted: map[string]bool{}}
}

func (s *SessionSecrets) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleted[key] {
		return "", ErrSecretNotFound
	}
	if v, ok := s.values[key]; ok {
		return v, nil
	}
	if s.primary != nil {
		return s.primary.Get(key)
	}
	return "", ErrSecretNotFound
}

func (s *SessionSecrets) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = value
	delete(s.deleted, key)
	if s.primary == nil {
		return nil
	}
	if err := s.primary.Set(key, value); err != nil {
		return fmt.Errorf("%w: %v", ErrSecretNotPersisted, err)
	}
	return nil
}

func (s *SessionSecrets) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.values, key)
	s.deleted[key] = true
	if s.primary != nil {
		return s.primary.Delete(key)
	}
	return nil
}
