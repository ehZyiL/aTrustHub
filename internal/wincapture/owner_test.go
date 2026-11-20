package wincapture

import (
	"errors"
	"net/netip"
	"testing"
)

func TestTCPUsesBothEndpoints(t *testing.T) {
	wanted := Tuple{netip.MustParseAddrPort("192.0.2.1:23000"), netip.MustParseAddrPort("192.0.2.2:443")}
	other := Tuple{wanted.Source, netip.MustParseAddrPort("192.0.2.3:443")}
	pid, err := MatchTCP(wanted, []TCPRow{{other, 9}, {wanted, 12}})
	if err != nil || pid != 12 {
		t.Fatalf("owner = %d, %v", pid, err)
	}
	if _, err = MatchTCP(wanted, []TCPRow{{other, 9}}); !errors.Is(err, ErrOwnerNotFound) {
		t.Fatalf("wrong remote: %v", err)
	}
	if _, err = MatchTCP(wanted, []TCPRow{{wanted, 9}, {wanted, 12}}); !errors.Is(err, ErrOwnerAmbiguous) {
		t.Fatalf("ambiguous: %v", err)
	}
	if _, err = MatchTCP(Tuple{}, nil); !errors.Is(err, ErrOwnerNotFound) {
		t.Fatal(err)
	}
}
