package process

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

type startupBlockingDevices struct {
	entered chan struct{}
	done    chan struct{}
}

func (s *startupBlockingDevices) LoadDevices(ctx context.Context, _ string) ([]contract.PairedDevice, error) {
	close(s.entered)
	defer close(s.done)
	<-ctx.Done()
	return nil, ctx.Err()
}

func (*startupBlockingDevices) SaveDevices(context.Context, string, []contract.PairedDevice) error {
	return nil
}

func TestRelayStartupContextCancellation(t *testing.T) {
	executable := buildRelayChild(t)
	identity, err := relay.GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	newOptions := func(ctx context.Context, store contract.DeviceStore) relay.ServerOptions {
		src := newTestSource("")
		t.Cleanup(func() { _ = src.Close() })
		return relay.ServerOptions{StartupContext: ctx, Identity: identity, Source: src, Token: "test-token", ShareID: "test-share", DeviceStore: store}
	}
	await := func(ch <-chan struct{}, description string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(3 * time.Second):
			t.Fatal(description)
		}
	}
	t.Run("already cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		server, err := Factory(executable)(newOptions(ctx, nil))
		if !errors.Is(err, context.Canceled) || server != nil {
			t.Fatalf("cancelled factory returned %v, %v", server, err)
		}
	})
	t.Run("pending handshake", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		store := &startupBlockingDevices{entered: make(chan struct{}), done: make(chan struct{})}
		opts := newOptions(ctx, store)
		result := make(chan error, 1)
		go func() {
			server, err := start(opts, executable)
			if server != nil {
				_ = server.Close(context.Background())
			}
			result <- err
		}()
		await(store.entered, "child did not reach device loading during startup")
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled startup returned %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("cancelled startup retained its child or broker")
		}
		await(store.done, "cancelled startup retained its device-load handler")
	})
	t.Run("running server survives caller cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		server, err := start(newOptions(ctx, &testDeviceStore{}), executable)
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close(context.Background())
		cancel()
		request, finish := context.WithTimeout(context.Background(), time.Second)
		defer finish()
		if _, err := server.PairControl(request, contract.PairCommand{Operation: "list"}); err != nil {
			t.Fatalf("startup context cancelled an established server: %v", err)
		}
	})
}
