package store

import (
	"errors"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
)

// RelayShareStore adapts the configuration and secret store to the relay
// controller. The controller never sees model.Config, and this file is the only
// place where the two shapes meet.
type RelayShareStore struct {
	Store *Store
}

var _ relay.Persistence = RelayShareStore{}

// ShareSettings reads the persisted share intent.
func (a RelayShareStore) ShareSettings() relay.Settings {
	share := a.Store.Config().Settings.LANShare
	var discovery *bool
	if share.DiscoveryEnabled != nil {
		// The store's snapshot must never share the pointer with the controller.
		enabled := *share.DiscoveryEnabled
		discovery = &enabled
	}
	return relay.Settings{
		Enabled:          share.Enabled,
		PointID:          share.PointID,
		InterfaceName:    share.InterfaceName,
		PreferredIPv4:    share.PreferredIPv4,
		Port:             share.Port,
		BoundPort:        share.BoundPort,
		ShareID:          share.ShareID,
		Fingerprint:      share.CertificateSHA256,
		DiscoveryEnabled: discovery,
		DiscoveryName:    share.DiscoveryName,
	}
}

// SaveShareSettings persists the share intent. Only Enabled is a user intent;
// the controller never stores Running.
func (a RelayShareStore) SaveShareSettings(s relay.Settings) error {
	_, err := a.Store.Update(func(cfg *model.Config) error {
		var discovery *bool
		if s.DiscoveryEnabled != nil {
			enabled := *s.DiscoveryEnabled
			discovery = &enabled
		}
		cfg.Settings.LANShare = model.LANShareSettings{
			Enabled:           s.Enabled,
			PointID:           s.PointID,
			InterfaceName:     s.InterfaceName,
			PreferredIPv4:     s.PreferredIPv4,
			Port:              s.Port,
			BoundPort:         s.BoundPort,
			ShareID:           s.ShareID,
			CertificateSHA256: s.Fingerprint,
			DiscoveryEnabled:  discovery,
			DiscoveryName:     s.DiscoveryName,
		}
		return nil
	})
	if err != nil {
		return err
	}
	return a.Store.Save()
}

// GetSecret reads a share secret from the same store the VPN passwords use.
func (a RelayShareStore) GetSecret(key string) (string, error) {
	return a.Store.secret(key)
}

// SetSecret writes a share secret. A refused write is an error, not a silent
// memory-only success: an unrecoverable sharing identity must not be announced.
func (a RelayShareStore) SetSecret(key, value string) error {
	return a.Store.setSecret(key, value)
}

// DeleteSecret removes a share secret.
func (a RelayShareStore) DeleteSecret(key string) error {
	err := a.Store.deleteSecret(key)
	if errors.Is(err, ErrSecretNotFound) {
		return nil
	}
	return err
}

// secret and friends keep the raw SecretStore reachable inside the package
// without exposing it to callers.
func (s *Store) secret(key string) (string, error) { return s.sec.Get(key) }

func (s *Store) setSecret(key, value string) error { return s.sec.Set(key, value) }

func (s *Store) deleteSecret(key string) error { return s.sec.Delete(key) }
