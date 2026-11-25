//go:build !windows

package discovery

import (
	"net"

	"golang.org/x/sys/unix"
)

// setMulticastLoopback asks the kernel to deliver this socket's multicast to
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
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP, value)
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
// POSIX does not fix the width of IP_MULTICAST_TTL: Linux reads an int, the BSDs
// read a single byte. The wider form is tried first and the narrower one is the
// fallback, so a stack that wants the other width ends up with 255 instead of
// silently keeping the default.
func setMulticastTTL(conn *net.UDPConn, ttl int) error {
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := rc.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, ttl)
		if setErr != nil {
			setErr = unix.SetsockoptByte(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, byte(ttl))
		}
	}); err != nil {
		return err
	}
	return setErr
}
