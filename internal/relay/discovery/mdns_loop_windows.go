//go:build windows

package discovery

import (
	"net"

	"golang.org/x/sys/windows"
)

// setMulticastLoopback asks the stack to deliver this socket's multicast to
// other sockets on the same host. Go creates these sockets with the option off
// (net.ListenMulticastUDP), which would hide two instances from each other.
func setMulticastLoopback(conn *net.UDPConn, on bool) error {
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	value := 0
	if on {
		value = 1
	}
	var setErr error
	if err := rc.Control(func(fd uintptr) {
		setErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_MULTICAST_LOOP, value)
	}); err != nil {
		return err
	}
	return setErr
}

// setMulticastTTL sets the hop limit of outgoing announcements. RFC 6762
// section 11 asks for 255 so a receiver can tell a link-local packet from one
// that crossed a router; the default of 1 still works between two instances of
// this app, which is why the caller treats a failure here as non-fatal.
//
// Windows takes IP_MULTICAST_TTL as a DWORD, which is what SetsockoptInt
// passes. (The matching getter returns a single byte; that quirk does not apply
// to setsockopt.)
func setMulticastTTL(conn *net.UDPConn, ttl int) error {
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := rc.Control(func(fd uintptr) {
		setErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_MULTICAST_TTL, ttl)
	}); err != nil {
		return err
	}
	return setErr
}
