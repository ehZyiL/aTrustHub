package wincapture

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsIPv4InterfaceAcceptsReturnedSitePrefix(t *testing.T) {
	// GetIpInterfaceEntry can return values that SetIpInterfaceEntry refuses
	// for IPv4. Model the API's rejection without touching host networking.
	for _, prefix := range []uint32{0, 24, 32, 128, 0xffffffff} {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			const index, luid = 7, 0x12345678
			sets := 0
			err := configureIPv4Interface(index, func(row *windows.MibIpInterfaceRow) error {
				if row.Family != windows.AF_INET || row.InterfaceIndex != index {
					t.Fatalf("wrong interface requested: %+v", row)
				}
				row.InterfaceLuid = luid
				row.SitePrefixLength = prefix
				row.BaseReachableTime = 30000
				row.WeakHostSend = 1
				return nil
			}, func(row *windows.MibIpInterfaceRow) error {
				sets++
				if row.SitePrefixLength != 0 {
					return windows.ERROR_INVALID_PARAMETER
				}
				if row.Family != windows.AF_INET || row.InterfaceIndex != index || row.InterfaceLuid != luid || row.BaseReachableTime != 30000 || row.WeakHostSend != 1 {
					t.Fatalf("unrelated interface parameters changed: %+v", row)
				}
				return nil
			})
			if err != nil || sets != 1 {
				t.Fatalf("interface update rejected: sets=%d err=%v", sets, err)
			}
		})
	}
}

func TestWindowsIPv4InterfaceErrorsIdentifyAPI(t *testing.T) {
	for _, failGet := range []bool{true, false} {
		t.Run(fmt.Sprintf("failGet=%v", failGet), func(t *testing.T) {
			sets := 0
			err := configureIPv4Interface(7, func(*windows.MibIpInterfaceRow) error {
				if failGet {
					return windows.ERROR_INVALID_PARAMETER
				}
				return nil
			}, func(*windows.MibIpInterfaceRow) error {
				sets++
				return windows.ERROR_INVALID_PARAMETER
			})
			api := "SetIpInterfaceEntry"
			if failGet {
				api = "GetIpInterfaceEntry"
				if sets != 0 {
					t.Fatal("wrote interface parameters after failed read")
				}
			}
			if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
				t.Fatalf("lost underlying error: %v", err)
			}
			for _, want := range []string{api, "Win32 87", "接口 7"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("missing %q in helper error: %v", want, err)
				}
			}
		})
	}
}
