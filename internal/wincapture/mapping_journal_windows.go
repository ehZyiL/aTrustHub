package wincapture

import (
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/ehZyiL/connect-hub/internal/dnsmapping"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const mappingRecoveryRoot = `SOFTWARE\ConnectHub\MappingRetirement`

type mappingReservation struct {
	Prefix  string
	Expires time.Time
}

func (r mappingReservation) validate() error {
	prefix, err := netip.ParsePrefix(r.Prefix)
	if err != nil || !dnsmapping.ValidPrefix(prefix) || r.Expires.IsZero() {
		return errors.New("映射退役记录无效")
	}
	return nil
}

// One registry value atomically records the last promised expiry before a DNS
// response is acknowledged. It outlives both the desktop and helper processes.
func saveMappingReservation(id, prefix string, expires time.Time) error {
	if !validID(id) {
		return errors.New("映射退役标识无效")
	}
	next := mappingReservation{Prefix: prefix, Expires: expires}
	if err := next.validate(); err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, mappingRecoveryRoot, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer key.Close()
	if data, _, readErr := key.GetStringValue(id); readErr == nil {
		var old mappingReservation
		if len(data) > 4096 || json.Unmarshal([]byte(data), &old) != nil || old.validate() != nil || old.Prefix != prefix {
			return errors.New("已有映射退役记录与本次身份冲突")
		}
		if old.Expires.After(next.Expires) {
			next.Expires = old.Expires
		}
	} else if !errors.Is(readErr, windows.ERROR_FILE_NOT_FOUND) {
		return readErr
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return key.SetStringValue(id, string(data))
}

func loadMappingReservations(now time.Time) ([]netip.Prefix, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, mappingRecoveryRoot, registry.QUERY_VALUE|registry.SET_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer key.Close()
	names, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}
	if len(names) > 256 {
		return nil, errors.New("映射退役记录过多，请先检查旧助手")
	}
	var result []netip.Prefix
	for _, name := range names {
		if !validID(name) {
			return nil, errors.New("映射退役记录标识损坏")
		}
		data, _, err := key.GetStringValue(name)
		if err != nil {
			return nil, err
		}
		var reservation mappingReservation
		if len(data) > 4096 || json.Unmarshal([]byte(data), &reservation) != nil || reservation.validate() != nil {
			return nil, errors.New("映射退役记录损坏，停止地址分配")
		}
		if now.Before(reservation.Expires) {
			result = append(result, netip.MustParsePrefix(reservation.Prefix))
		} else if err := key.DeleteValue(name); err != nil {
			return nil, err
		}
	}
	return result, nil
}
