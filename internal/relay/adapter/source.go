package adapter

import (
	"context"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

// SourceAdapter binds sharing to the Manager's already authorized source and a
// copied configuration. The Manager retains its endpoint/generation checks;
// this adapter can neither log in another gateway nor widen its permissions.
type SourceAdapter struct {
	Acquire func(context.Context, string) (contract.Source, error)
	Config  func() model.Config
}

func (a SourceAdapter) AcquireSource(ctx context.Context, id string) (contract.Source, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a.Acquire == nil {
		return nil, contract.ErrPointNotReady
	}
	return a.Acquire(ctx, id)
}
func (a SourceAdapter) PointName(id string) string {
	if a.Config == nil {
		return ""
	}
	cfg := a.Config()
	if p := cfg.Find(id); p != nil {
		return p.Name
	}
	return ""
}
func (a SourceAdapter) PointExists(id string) bool {
	if a.Config == nil {
		return false
	}
	cfg := a.Config()
	return cfg.Find(id) != nil
}
