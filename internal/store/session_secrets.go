package store

import "sync"

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
	if s.primary != nil {
		_ = s.primary.Set(key, value)
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
