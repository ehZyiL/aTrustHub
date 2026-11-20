package wincapture

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/sagernet/sing/common/winiphlpapi"
	"golang.org/x/sys/windows"
)

func tcpRows(ipv4 bool) ([]TCPRow, error) {
	var out []TCPRow
	if ipv4 {
		rows, err := winiphlpapi.GetExtendedTcpTable()
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out = append(out, TCPRow{Tuple: Tuple{
				Source:      netip.AddrPortFrom(winiphlpapi.DwordToAddr(row.DwLocalAddr), winiphlpapi.DwordToPort(row.DwLocalPort)),
				Destination: netip.AddrPortFrom(winiphlpapi.DwordToAddr(row.DwRemoteAddr), winiphlpapi.DwordToPort(row.DwRemotePort)),
			}, PID: row.DwOwningPid})
		}
	} else {
		rows, err := winiphlpapi.GetExtendedTcp6Table()
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out = append(out, TCPRow{Tuple: Tuple{
				Source:      netip.AddrPortFrom(netip.AddrFrom16(row.UcLocalAddr), winiphlpapi.DwordToPort(row.DwLocalPort)),
				Destination: netip.AddrPortFrom(netip.AddrFrom16(row.UcRemoteAddr), winiphlpapi.DwordToPort(row.DwRemotePort)),
			}, PID: row.DwOwningPid})
		}
	}
	return out, nil
}

// Owner pins a process handle while its creation time and job are checked.
// PID reuse must never inherit an earlier application's capture permission.
type Owner struct {
	Identity
	handle windows.Handle
}

func (o *Owner) Close() error                           { return windows.CloseHandle(o.handle) }
func (o *Owner) InJob(job windows.Handle) (bool, error) { return inJob(o.handle, job) }

func LookupTCP(ctx context.Context, tuple Tuple) (*Owner, error) {
	if tuple.Source.Addr().Zone() != "" || tuple.Destination.Addr().Zone() != "" {
		return nil, ErrOwnerNotFound
	}
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rows, err := tcpRows(tuple.Source.Addr().Is4())
		if err != nil {
			return nil, err
		}
		pid, err := MatchTCP(tuple, rows)
		if err == nil {
			h, openErr := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
			if openErr != nil {
				return nil, openErr
			}
			identity, idErr := processIdentity(h, pid)
			// Recheck after pinning the process; a PID/table entry may have
			// disappeared between the first snapshot and OpenProcess.
			again, readErr := tcpRows(tuple.Source.Addr().Is4())
			confirmed, matchErr := MatchTCP(tuple, again)
			state, waitErr := windows.WaitForSingleObject(h, 0)
			if idErr == nil && readErr == nil && matchErr == nil && confirmed == pid && waitErr == nil && state == uint32(windows.WAIT_TIMEOUT) {
				return &Owner{Identity: identity, handle: h}, nil
			}
			windows.CloseHandle(h)
			if idErr != nil || readErr != nil || waitErr != nil {
				return nil, errors.Join(idErr, readErr, waitErr)
			}
			if errors.Is(matchErr, ErrOwnerAmbiguous) {
				return nil, matchErr
			}
		} else if !errors.Is(err, ErrOwnerNotFound) {
			return nil, err
		}
		if attempt == 3 {
			break
		}
		timer := time.NewTimer(15 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, ErrOwnerNotFound
}

// UDP tables have no remote endpoint. Accept only one unique owning PID;
// shared ports/services cannot be assigned to a selected application safely.
func LookupUDP(ctx context.Context, source netip.AddrPort) (*Owner, error) {
	if !source.Addr().Is4() {
		return nil, ErrOwnerNotFound
	}
	lookup := func() (uint32, error) {
		rows, err := winiphlpapi.GetExtendedUdpTable()
		if err != nil {
			return 0, err
		}
		var pid uint32
		for _, row := range rows {
			addr := winiphlpapi.DwordToAddr(row.DwLocalAddr)
			if winiphlpapi.DwordToPort(row.DwLocalPort) != source.Port() || addr != source.Addr() && !addr.IsUnspecified() {
				continue
			}
			if row.DwOwningPid == 0 {
				return 0, ErrOwnerNotFound
			}
			if pid != 0 && pid != row.DwOwningPid {
				return 0, ErrOwnerAmbiguous
			}
			pid = row.DwOwningPid
		}
		if pid == 0 {
			return 0, ErrOwnerNotFound
		}
		return pid, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pid, err := lookup()
	if err != nil {
		return nil, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return nil, err
	}
	identity, idErr := processIdentity(h, pid)
	confirmed, readErr := lookup()
	state, waitErr := windows.WaitForSingleObject(h, 0)
	if idErr != nil || readErr != nil || confirmed != pid || waitErr != nil || state != uint32(windows.WAIT_TIMEOUT) {
		windows.CloseHandle(h)
		return nil, errors.Join(ErrOwnerNotFound, idErr, readErr, waitErr)
	}
	return &Owner{Identity: identity, handle: h}, nil
}
