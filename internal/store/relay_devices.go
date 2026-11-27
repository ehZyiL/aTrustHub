package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

// Device grants are public verification keys, persisted separately from share
// intent. Atomic replacement never mutates config memory before disk succeeds.
func (a RelayShareStore) LoadDevices(ctx context.Context, sid string) ([]contract.PairedDevice, error) {
	if !model.ValidShareID(sid) {
		return nil, errors.New("invalid share identity")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path := filepath.Join(a.Store.dir, "relay-devices", sid+".json")
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Size() > 128<<10 {
		return nil, errors.New("device store exceeds limit")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []contract.PairedDevice
	if err = json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	if len(out) > contract.MaxPairedDevices {
		return nil, errors.New("too many devices")
	}
	return out, nil
}

func (a RelayShareStore) SaveDevices(ctx context.Context, sid string, devices []contract.PairedDevice) error {
	if !model.ValidShareID(sid) || len(devices) > contract.MaxPairedDevices {
		return errors.New("invalid device store")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(devices)
	if err != nil {
		return err
	}
	if len(data) > 128<<10 {
		return errors.New("device store exceeds limit")
	}
	dir := filepath.Join(a.Store.dir, "relay-devices")
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, sid+".json"), data, 0o600)
}
