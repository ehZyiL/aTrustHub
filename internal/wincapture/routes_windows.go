package wincapture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ipHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var initializeRoute = ipHelper.NewProc("InitializeIpForwardEntry")
var createRoute = ipHelper.NewProc("CreateIpForwardEntry2")
var deleteRoute = ipHelper.NewProc("DeleteIpForwardEntry2")

func routeRows() ([]Route, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, windowsError("读取 IPv4 路由 GetIpForwardTable2", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	metrics := map[uint32]uint32{}
	var out []Route
	for _, row := range table.Rows() {
		metric, ok := metrics[row.InterfaceIndex]
		if !ok {
			iface := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: row.InterfaceIndex}
			if err := windows.GetIpInterfaceEntry(&iface); err != nil {
				return nil, fmt.Errorf("读取路由接口 %d：%w", row.InterfaceIndex, windowsError("GetIpInterfaceEntry", err))
			}
			if iface.Connected == 0 {
				continue
			}
			metric = iface.Metric
			metrics[row.InterfaceIndex] = metric
		}
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
		if a.Family != windows.AF_INET {
			continue
		}
		p := netip.PrefixFrom(netip.AddrFrom4(a.Addr), int(row.DestinationPrefix.PrefixLength)).Masked()
		out = append(out, Route{p, row.InterfaceIndex, uint64(row.Metric) + uint64(metric)})
	}
	return out, nil
}

func addRoute(index uint32, prefix netip.Prefix) (*windows.MibIpForwardRow2, error) {
	if index == 0 || !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() == 0 {
		return nil, errors.New("拒绝无效或默认接管路由")
	}
	var row windows.MibIpForwardRow2
	initializeRoute.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceIndex = index
	row.DestinationPrefix.PrefixLength = uint8(prefix.Bits())
	*(*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix)) = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: prefix.Masked().Addr().As4()}
	*(*windows.RawSockaddrInet4)(unsafe.Pointer(&row.NextHop)) = windows.RawSockaddrInet4{Family: windows.AF_INET}
	row.Metric = 0
	code, _, _ := createRoute.Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 {
		return nil, fmt.Errorf("路由 %s（接口 %d）：%w", prefix, index, windowsError("CreateIpForwardEntry2", syscall.Errno(code)))
	}
	return &row, nil
}

func removeRoute(row *windows.MibIpForwardRow2) error {
	code, _, _ := deleteRoute.Call(uintptr(unsafe.Pointer(row)))
	if code == 0 || syscall.Errno(code) == windows.ERROR_NOT_FOUND {
		return nil
	}
	return windowsError("删除接管路由 DeleteIpForwardEntry2", syscall.Errno(code))
}

// Binding the outgoing socket excludes our adapter without modifying the
// application's global default route. Routes are reread for every new dial,
// so a disappeared Tailscale/physical interface cannot use a stale snapshot.
func originalDial(ctx context.Context, network, address string, excluded uint32) (net.Conn, error) {
	destination, err := netip.ParseAddrPort(address)
	if err != nil || !destination.Addr().Is4() {
		return nil, errors.New("原出口拨号需要 IPv4 地址")
	}
	routes, err := routeRows()
	if err != nil {
		return nil, err
	}
	route, err := OriginalRoute(destination.Addr(), routes, excluded)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 15 * time.Second}
	dialer.ControlContext = func(_ context.Context, network, _ string, raw syscall.RawConn) error {
		if strings.HasSuffix(network, "6") {
			return errors.New("暂不支持 IPv6")
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], route.Interface)
		index := *(*uint32)(unsafe.Pointer(&b[0]))
		var bindErr error
		err := raw.Control(func(fd uintptr) {
			bindErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(index))
		})
		return errors.Join(err, bindErr)
	}
	return dialer.DialContext(ctx, network, address)
}
