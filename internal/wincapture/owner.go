// Package wincapture implements the Windows per-application capture backend.
// Policy and tuple matching are platform independent so they can be tested
// without changing the developer machine's network.
package wincapture

import (
	"errors"
	"net/netip"
)

var (
	ErrOwnerNotFound  = errors.New("未找到连接所属进程")
	ErrOwnerAmbiguous = errors.New("连接所属进程不唯一，已拒绝接管")
)

type Identity struct {
	PID     uint32 `json:"pid"`
	Created uint64 `json:"created"`
}

type Tuple struct{ Source, Destination netip.AddrPort }

type TCPRow struct {
	Tuple
	PID uint32
}

// MatchTCP uses both endpoints. Matching only a local port can confuse
// simultaneous connections, especially while an application is restarting.
func MatchTCP(tuple Tuple, rows []TCPRow) (uint32, error) {
	if !tuple.Source.IsValid() || !tuple.Destination.IsValid() || tuple.Source.Port() == 0 || tuple.Destination.Port() == 0 {
		return 0, ErrOwnerNotFound
	}
	var pid uint32
	for _, row := range rows {
		if row.Tuple != tuple || row.PID == 0 {
			continue
		}
		if pid != 0 && pid != row.PID {
			return 0, ErrOwnerAmbiguous
		}
		pid = row.PID
	}
	if pid == 0 {
		return 0, ErrOwnerNotFound
	}
	return pid, nil
}
