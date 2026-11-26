package main

import (
	"context"
	"fmt"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	relayadapter "github.com/ehzyil/connect-hub/internal/relay/adapter"
	relayclient "github.com/ehzyil/connect-hub/internal/relay/client"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

// setupLANShare is composition only. Pages retain the client interface.
func (a *app) setupLANShare() {
	a.lanShare = relayclient.NewLocal(relay.NewController(
		store.RelayShareStore{Store: a.store}, relayadapter.SourceAdapter{
			Acquire: func(ctx context.Context, id string) (relay.Source, error) {
				if a.mgr == nil {
					return nil, relay.ErrPointNotReady
				}
				return a.mgr.AcquireRelayShareSource(id)
			}, Config: a.configForBackground,
		}, lanAddresses{},
		func(format string, args ...any) {
			if a.bus != nil {
				a.bus.Add("app", fmt.Sprintf(format, args...))
			}
		}, a.lanShareChanged,
	))
	a.relayCheck = func(ctx context.Context, code relay.ShareCode) ([]string, error) {
		return relay.FormatReport(relay.Diagnose(ctx, code, relay.DiagnoseOptions{})), nil
	}
	a.lanShareUI.results = make(chan lanShareResult, 4)
	a.setupLANDiscovery()
}

func (a *app) relayConnector() vpn.Registration {
	return vpn.Registration{Protocol: model.ProtocolLANRelay, Connect: relayadapter.NewConnector(relayadapter.Options{
		Dial: relay.DirectDialer, SaveSnapshot: a.saveRelaySnapshot,
	})}
}
