package wincapture

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestElevationCancellationDoesNotWaitForConsentOrSpawnAnotherPrompt(t *testing.T) {
	prompt := elevationPrompt{busy: make(chan struct{}, 1)}
	started, consent := make(chan struct{}), make(chan struct{})
	var once sync.Once
	complete := func() { once.Do(func() { close(consent) }) }
	defer complete()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- prompt.run(ctx, func() error {
			close(started)
			<-consent
			return nil
		})
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop waited for OS consent")
	}
	if err := prompt.run(context.Background(), func() error {
		t.Error("opened a competing OS prompt")
		return nil
	}); err == nil {
		t.Fatal("pending OS prompt was forgotten")
	}
	complete()
	deadline := time.After(time.Second)
	for len(prompt.busy) != 0 {
		select {
		case <-deadline:
			t.Fatal("completed consent did not release prompt slot")
		case <-time.After(time.Millisecond):
		}
	}
	want := errors.New("consent denied")
	if err := prompt.run(context.Background(), func() error { return want }); !errors.Is(err, want) {
		t.Fatal("retry lost denial reason", err)
	}
	if err := prompt.run(ctx, func() error {
		t.Error("cancelled launch opened UAC")
		return nil
	}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
