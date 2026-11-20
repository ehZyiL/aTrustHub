package wincapture

import (
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func configureAdapter(index uint32, address netip.Prefix) error {
	var row windows.MibUnicastIpAddressRow
	ipHelper.NewProc("InitializeUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceIndex = index
	row.OnLinkPrefixLength = uint8(address.Bits())
	row.DadState = 4 // IpDadStatePreferred
	*(*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address)) = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: address.Addr().As4()}
	code, _, _ := ipHelper.NewProc("CreateUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 {
		return fmt.Errorf("配置接管网卡地址（接口 %d，%s）：%w", index, address, windowsError("CreateUnicastIpAddressEntry", syscall.Errno(code)))
	}
	return configureIPv4Interface(index, windows.GetIpInterfaceEntry, func(iface *windows.MibIpInterfaceRow) error {
		code, _, _ := ipHelper.NewProc("SetIpInterfaceEntry").Call(uintptr(unsafe.Pointer(iface)))
		if code != 0 {
			return syscall.Errno(code)
		}
		return nil
	})
}

// Keep Get/Set injectable so the native tests can reproduce Windows returning
// an unwritable SitePrefixLength without creating an adapter or changing routes.
func configureIPv4Interface(index uint32, get, set func(*windows.MibIpInterfaceRow) error) error {
	iface := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: index}
	if err := get(&iface); err != nil {
		return fmt.Errorf("读取接管网卡参数（接口 %d）：%w", index, windowsError("GetIpInterfaceEntry", err))
	}
	// sing-tun's internal/winipcfg also normalizes this field after Get.
	// The IPv4 Set contract requires zero, including when Get returns a
	// nonzero value or the 0xffffffff sentinel. Preserve all other fields.
	// https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry
	iface.SitePrefixLength = 0
	iface.NlMtu, iface.Metric, iface.UseAutomaticMetric, iface.DadTransmits = 1400, 0, 0, 0
	iface.RouterDiscoveryBehavior = 0 // RouterDiscoveryDisabled
	if err := set(&iface); err != nil {
		return fmt.Errorf("写入接管网卡参数（接口 %d，MTU %d，SitePrefixLength %d）：%w", index, iface.NlMtu, iface.SitePrefixLength, windowsError("SetIpInterfaceEntry", err))
	}
	return nil
}
