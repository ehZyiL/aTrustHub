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
