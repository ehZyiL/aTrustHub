package localapps

import "context"

// SystemCapture shares the application's DNS publishers and platform runtime.
// Add registers a new generation without replacing previously registered ones.
type SystemCapture interface {
	Add(context.Context, CaptureConfig) error
	Done() <-chan struct{}
	Err() error
	Close() error
}
