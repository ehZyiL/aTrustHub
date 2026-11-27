package process

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

type pairCommandBuffer struct{ bytes.Buffer }

func (*pairCommandBuffer) Close() error { return nil }

func TestShareRegressionAlreadyCancelledPairControlDoesNotSend(t *testing.T) {
	var commands pairCommandBuffer
	server := &processServer{
		pairing: true,
		stdin:   &commands,
		rpc:     make(map[uint64]chan event),
		done:    make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := server.PairControl(ctx, contract.PairCommand{Operation: "cancel"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled command returned %v", err)
	}
	if commands.Len() != 0 {
		t.Errorf("already-cancelled PairControl still wrote %d bytes of IPC", commands.Len())
	}
}

type queuedWriteContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *queuedWriteContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestCancelledPairControlWhileWriterBusyDoesNotSend(t *testing.T) {
	var commands pairCommandBuffer
	server := &processServer{pairing: true, stdin: &commands, rpc: make(map[uint64]chan event), done: make(chan struct{})}
	server.writeMu.Lock()
	unlock := sync.OnceFunc(server.writeMu.Unlock)
	defer unlock()
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &queuedWriteContext{Context: base, waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := server.PairControl(ctx, contract.PairCommand{Operation: "cancel"})
		result <- err
	}()
	select {
	case <-ctx.waiting:
	case <-time.After(time.Second):
		t.Fatal("PairControl did not queue for writer")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("queued writer returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled PairControl still waits for IPC writer")
	}
	unlock()
	if err := server.send(command{Operation: "revoke"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(commands.String(), "pair-control") || len(server.rpc) != 0 {
		t.Fatalf("cancelled request left IPC or RPC state: %q, %d", commands.String(), len(server.rpc))
	}
}
