package wincapture

import (
	"golang.org/x/sys/windows"
	"testing"
)

func TestRouteCleanupComparesOwnedValuesAndIsIdempotent(t *testing.T) {
	expected := windows.MibIpForwardRow2{InterfaceIndex: 7, Metric: 0, Protocol: 3}
	removed := 0
	remove := func(*windows.MibIpForwardRow2) error { removed++; return nil }
	for _, mutate := range []func(*windows.MibIpForwardRow2){
		func(r *windows.MibIpForwardRow2) { r.Metric++ },
		func(r *windows.MibIpForwardRow2) { r.InterfaceIndex++ },
		func(r *windows.MibIpForwardRow2) { r.Protocol++ },
	} {
		err := removeOwnedRoute(&expected, func(r *windows.MibIpForwardRow2) error { mutate(r); return nil }, remove)
		if err == nil || removed != 0 {
			t.Fatal("external route change deleted")
		}
	}
	if err := removeOwnedRoute(&expected, func(*windows.MibIpForwardRow2) error { return windows.ERROR_NOT_FOUND }, remove); err != nil || removed != 0 {
		t.Fatal("missing route not idempotent", err)
	}
	if err := removeOwnedRoute(&expected, func(r *windows.MibIpForwardRow2) error { r.Age = 10; return nil }, remove); err != nil || removed != 1 {
		t.Fatal("ordinary route aging blocked cleanup", err)
	}
}
