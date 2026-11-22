package main

import (
	"errors"

	"github.com/egoist/mygo"

	"github.com/ehzyil/connect-hub/internal/store"
)

// keychainSecrets keeps the access points' creds in the system credential
// store: the macOS keychain, the Secret Service on Linux, the Credential
// Manager on Windows. There is deliberately no plaintext fallback file: when
// the store refuses a write, SessionSecrets keeps the value for this run and
// reports store.ErrSecretNotPersisted so the UI can say so.
type keychainSecrets struct{}

func (keychainSecrets) Get(key string) (string, error) {
	value, err := mygo.Secrets.Get(key)
	switch {
	case errors.Is(err, mygo.ErrSecretNotFound):
		return "", store.ErrSecretNotFound
	case err != nil:
		return "", err
	}
	return string(value), nil
}

func (keychainSecrets) Set(key, value string) error {
	return mygo.Secrets.Set(key, []byte(value))
}

func (keychainSecrets) Delete(key string) error {
	return mygo.Secrets.Delete(key)
}
