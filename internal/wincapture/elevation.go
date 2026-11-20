package wincapture

import (
	"context"
	"errors"
)

// Windows owns the consent dialog; cancelling a launch cannot dismiss it.
// Keep at most one outstanding OS prompt, but let the caller close its pipe
// immediately. A helper approved later then has no live channel to configure.
type elevationPrompt struct {
	busy chan struct{}
}

func (p elevationPrompt) run(ctx context.Context, launch func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case p.busy <- struct{}{}:
	default:
		return errors.New("上一次 Windows 授权提示尚未关闭，请先处理该提示后重试")
	}
	result := make(chan error, 1)
	go func() {
		err := ctx.Err()
		if err == nil {
			err = launch()
		}
		<-p.busy
		result <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-result:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
}
