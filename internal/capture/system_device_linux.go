package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"

	tun "github.com/mythologyli/sing-tun"
	"github.com/ehZyiL/connect-hub/internal/packetstack"
	"golang.org/x/sys/unix"
)

type systemDevice struct {
	tun.Tun
	name string
}

// Open a nonpersistent device. Closing the descriptor, including on process
// death, removes the interface and the kernel routes attached to it.
func openSystemDevice(ctx context.Context, run commandFunc, id string, source netip.Addr) (*systemDevice, error) {
	if !sessionPattern.MatchString(id) || !netip.MustParsePrefix("198.18.0.0/16").Contains(source) {
		return nil, errors.New("capture: invalid system TUN identity")
	}
	name := "echt" + id[:10]
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("capture: open system TUN: %w", err)
	}
	req, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	// An existing name must never be attached, even if the existing device
	// has the exact same type and flags.
	req.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_TUN_EXCL)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, req); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("capture: create system TUN: %w", err)
	}
	// sing-tun's default constructor also enables a global DNS routing
	// domain. Adopting the descriptor keeps those side effects out of this
	// backend; the helper owns the limited routes and DNS link explicitly.
	handle, err := tun.New(tun.Options{FileDescriptor: fd})
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	d := &systemDevice{Tun: handle, name: name}
	if _, err := run(ctx, "ip", "", "-4", "addr", "add", source.String()+"/32", "dev", name); err != nil {
		return nil, errors.Join(err, d.Close())
	}
	if _, err := run(ctx, "ip", "", "link", "set", "dev", name, "mtu", fmt.Sprint(packetstack.MTU), "up"); err != nil {
		return nil, errors.Join(err, d.Close())
	}
	return d, nil
}

func (d *systemDevice) ReadPacket() ([]byte, error) {
	data := make([]byte, packetstack.MTU)
	n, err := d.Read(data)
	return data[:n], err
}

func (d *systemDevice) WritePacket(data []byte) error {
	n, err := d.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

var _ packetstack.Device = (*systemDevice)(nil)
