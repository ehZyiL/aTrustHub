package client

import (
	"context"
	discovery "github.com/ehzyil/connect-hub/internal/relay/discovery/contract"
)

type Publisher interface {
	Set(discovery.Announcement)
	Clear()
	Status() discovery.Status
	Close(context.Context) error
}

type Browser interface {
	Start([]discovery.Interface) error
	Refresh() error
	Snapshot() discovery.Snapshot
	Err() string
	Close() error
	Shutdown() error
}
