package wincapture

import (
	"io"

	tun "github.com/mythologyli/sing-tun"
)

type wintunPackets struct{ tun.WinTun }

func (d wintunPackets) ReadPacket() ([]byte, error) {
	// Keep the driver's session reference through the copy when possible so
	// adapter shutdown cannot race a read.
	if reader, ok := d.WinTun.(interface{ ReadFunc(func([]byte)) error }); ok {
		var data []byte
		err := reader.ReadFunc(func(packet []byte) { data = append([]byte(nil), packet...) })
		return data, err
	}
	packet, release, err := d.WinTun.ReadPacket()
	if err != nil {
		return nil, err
	}
	defer release()
	return append([]byte(nil), packet...), nil
}

func (d wintunPackets) WritePacket(data []byte) error {
	n, err := d.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}
