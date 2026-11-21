package capture

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/ehZyiL/connect-hub/internal/dnsmapping"
	"github.com/ehZyiL/connect-hub/internal/resolved"
)

type systemJournal struct {
	Routes systemRoutes
	DNS    *resolved.Lease
	Pools  map[string]int64
}

func (j systemJournal) validate() error {
	if err := j.Routes.validate(); err != nil {
		return err
	}
	if len(j.Pools) > 16 {
		return errors.New("capture: invalid system alias journal")
	}
	for raw, expiry := range j.Pools {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !dnsmapping.ValidPrefix(prefix) || expiry <= 0 {
			return errors.New("capture: invalid system alias reservation")
		}
	}
	if j.DNS != nil {
		return j.DNS.Validate()
	}
	return nil
}

func loadSystemJournal(path string) (systemJournal, error) {
	var journal systemJournal
	if err := readOwnedJournal(path, &journal); err != nil {
		return journal, err
	}
	return journal, journal.validate()
}

func (j systemJournal) save(path string) error {
	if err := j.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return writeOwnedJournal(path, data)
}

func (s *Service) systemJournalPath() string { return filepath.Join(s.dir, "system-tun.json") }

func recoverSystemJournal(ctx context.Context, run commandFunc, path string) error {
	journal, err := loadSystemJournal(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if journal.DNS != nil {
		if err := resolved.Remove(ctx, resolved.Command(run), *journal.DNS); err != nil {
			return err
		}
		journal.DNS = nil
	}
	if err := journal.Routes.removeRule(ctx, run); err != nil {
		return err
	}
	now, err := bootNow()
	if err != nil {
		return err
	}
	for pool, expiry := range journal.Pools {
		if now >= expiry {
			delete(journal.Pools, pool)
		}
	}
	if len(journal.Pools) == 0 {
		return os.Remove(path)
	}
	return journal.save(path)
}
