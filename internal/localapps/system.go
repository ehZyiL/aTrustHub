package localapps

import "context"

// SystemCapture shares the application's DNS publishers and platform runtime.
// Reconcile updates gateway generations while keeping resource routes covered.
type SystemCapture interface {
	Reconcile(context.Context, []CaptureConfig) error
	Done() <-chan struct{}
	Err() error
	Close() error
}
