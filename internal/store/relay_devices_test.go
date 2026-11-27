package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

func TestRelayDevicesAtomicPersistenceAndBounds(t *testing.T) {
	store := relayTestStore(t)
	a := RelayShareStore{Store: store}
	sid := relayTestPoint().Relay.ShareID
	ctx := context.Background()
	devices := []contract.PairedDevice{{ID: "public-verifier", PublicKey: []byte("public-key"), Name: "device"}}
	if err := a.SaveDevices(ctx, sid, devices); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(store.Dir(), store.sec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := (RelayShareStore{Store: reopened}).LoadDevices(ctx, sid)
	if err != nil || len(got) != 1 || got[0].ID != devices[0].ID {
		t.Fatal("grant lost", err)
	}
	if err = a.SaveDevices(ctx, "../escape", devices); err == nil {
		t.Fatal("path traversal accepted")
	}
	if err = a.SaveDevices(ctx, sid, make([]contract.PairedDevice, contract.MaxPairedDevices+1)); err == nil {
		t.Fatal("unbounded grants")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err = a.SaveDevices(cancelled, sid, nil); err == nil {
		t.Fatal("cancelled write succeeded")
	}
	got, err = a.LoadDevices(ctx, sid)
	if err != nil || len(got) != 1 {
		t.Fatal("failed write lost prior grant")
	}
	path := filepath.Join(store.Dir(), "relay-devices", sid+".json")
	if err = os.WriteFile(path, []byte(strings.Repeat("x", (128<<10)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = a.LoadDevices(ctx, sid); err == nil {
		t.Fatal("oversized record loaded")
	}
}
