package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ehZyiL/connect-hub/internal/workeripc"
	"golang.org/x/sys/unix"
)

const aliasJournalLimit = 1 << 20
const aliasRetireGrace = 5 * time.Second

type aliasRecord struct {
	Original string `json:"original"`
	Expires  int64  `json:"expiresBootNs"`
}

// Alias state is kept in /run for this boot only. Expiry uses CLOCK_BOOTTIME
// so suspend and wall-clock corrections cannot extend a cached destination.
// The journal never preserves permission to enter a VPN, only original-path
// restoration and the requirement to reserve this prefix until it expires.
type aliasJournal struct {
	Version int                    `json:"version"`
	ID      string                 `json:"id"`
	UID     int                    `json:"uid"`
	Prefix  string                 `json:"prefix"`
	Entries map[string]aliasRecord `json:"entries"`
}

func bootNow() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return ts.Nano(), nil
}

func (j aliasJournal) validate(uid int) error {
	a := aliasRoute{ID: j.ID, UID: j.UID, Prefix: j.Prefix}
	if j.Version != 1 || j.UID != uid || len(j.Entries) > 4094 || a.validate() != nil {
		return errors.New("capture: invalid alias journal")
	}
	p := netip.MustParsePrefix(j.Prefix)
	for address, entry := range j.Entries {
		fake, e1 := netip.ParseAddr(address)
		real, e2 := netip.ParseAddr(entry.Original)
		if e1 != nil || e2 != nil || fake.String() != address || !p.Contains(fake) || !real.Is4() || real.String() != entry.Original || !real.IsGlobalUnicast() || real.IsLoopback() || real.IsLinkLocalUnicast() || p.Contains(real) || entry.Expires < 0 {
			return errors.New("capture: invalid journalled alias destination")
		}
	}
	return nil
}

func saveAliasJournal(dir string, j aliasJournal) error {
	if err := j.validate(j.UID); err != nil {
		return err
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(b) > aliasJournalLimit {
		return errors.New("capture: alias journal too large")
	}
	f, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), filepath.Join(dir, j.ID+".json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func readAliasJournal(path string, uid int) (j aliasJournal, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return j, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return j, err
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || s.Size() > aliasJournalLimit {
		return j, errors.New("capture: unsafe alias journal")
	}
	d := json.NewDecoder(io.LimitReader(f, aliasJournalLimit+1))
	d.DisallowUnknownFields()
	if err = d.Decode(&j); err != nil {
		return j, err
	}
	if d.Decode(new(any)) != io.EOF {
		return j, errors.New("capture: trailing alias journal data")
	}
	if err = j.validate(uid); err != nil {
		return j, err
	}
	if filepath.Base(path) != j.ID+".json" {
		return j, errors.New("capture: alias journal name mismatch")
	}
	return j, nil
}

func (j aliasJournal) retirement() int64 {
	var last int64
	for _, r := range j.Entries {
		if r.Expires > last {
			last = r.Expires
		}
	}
	if last > 0 {
		last += int64(aliasRetireGrace)
	}
	return last
}

// publishSaved must run under the service's transaction lock. Persist first,
// then publish the map, then allow the DNS response out of the process. A
// failed publication may reserve an unused address but never loses recovery.
func (a *aliasRoute) publishSaved(ctx context.Context, run commandFunc, dir string, j *aliasJournal, aliases []workeripc.DNSAlias) error {
	if len(aliases) > 32 {
		return errors.New("capture: alias publication batch too large")
	}
	if j.ID != a.ID || j.UID != a.UID || j.Prefix != a.Prefix {
		return errors.New("capture: alias journal/session mismatch")
	}
	now, err := bootNow()
	if err != nil {
		return err
	}
	prepared := *j
	prepared.Entries = make(map[string]aliasRecord, len(j.Entries)+len(aliases))
	for address, r := range j.Entries {
		prepared.Entries[address] = r
	}
	for _, alias := range aliases {
		if alias.TTL < 1 || alias.TTL > 60 {
			return errors.New("capture: invalid alias lifetime")
		}
		entry := aliasRecord{Original: alias.Original, Expires: now + int64((time.Duration(alias.TTL)+2)*time.Second)}
		if old, ok := prepared.Entries[alias.Address]; ok {
			if old.Original != entry.Original {
				return errors.New("capture: cannot retarget a journalled alias")
			}
			if old.Expires > entry.Expires {
				entry.Expires = old.Expires
			}
		}
		prepared.Entries[alias.Address] = entry
	}
	if err = saveAliasJournal(dir, prepared); err != nil {
		return err
	}
	*j = prepared
	return a.publish(ctx, run, aliases)
}

// restoreAliasJournal discards every selected scope after a helper crash and
// restores only still-cacheable direct destinations. The table replacement is
// atomic; unrelated state is untouched. Caller schedules removal at retirement.
func restoreAliasJournal(ctx context.Context, run commandFunc, j aliasJournal, now int64) (*aliasRoute, error) {
	if err := j.validate(j.UID); err != nil {
		return nil, err
	}
	a := &aliasRoute{ID: j.ID, UID: j.UID, Prefix: j.Prefix, issued: map[string]string{}, expires: map[string]int64{}}
	state, err := snapshot(ctx, run)
	if err != nil {
		return nil, err
	}
	exists, ours := namedTableOwned(state, "ip", a.table(), a.owner())
	if exists && !ours {
		return nil, errors.New("capture: recovery alias table belongs to another owner")
	}
	var script strings.Builder
	if exists {
		fmt.Fprintf(&script, "delete table ip %s\n", a.table())
	}
	script.WriteString(a.installScript())
	for address, entry := range j.Entries {
		a.issued[address] = entry.Original
		if entry.Expires <= now {
			continue
		}
		remaining := time.Duration(entry.Expires - now)
		if remaining > 63*time.Second {
			return nil, errors.New("capture: journal expiry exceeds the bounded DNS lifetime")
		}
		seconds := int64((remaining + time.Second - 1) / time.Second)
		fmt.Fprintf(&script, "add element ip %s real { %s timeout %ds : %s }\n", a.table(), address, seconds, entry.Original)
		a.expires[address] = entry.Expires
	}
	if _, err = run(ctx, "nft", script.String(), "-f", "-"); err != nil {
		return nil, err
	}
	a.digest, err = a.configurationDigest(ctx, run)
	return a, err
}
