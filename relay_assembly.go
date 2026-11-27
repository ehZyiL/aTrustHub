package main

import (
	"context"
	"fmt"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	relayadapter "github.com/ehzyil/connect-hub/internal/relay/adapter"
	relayclient "github.com/ehzyil/connect-hub/internal/relay/client"
	relayprocess "github.com/ehzyil/connect-hub/internal/relay/process"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

// setupLANShare is composition only. Pages retain the client interface.
func (a *app) setupLANShare() {
	executable := a.relayComponentPath()
	if executable == "" {
		a.lanShare = relayclient.Unavailable("缺少局域网分享组件 connect-hub-relay，请使用包含 core/connect-hub-relay 的完整安装包；基础 VPN 仍可使用")
	} else {
		controller := relay.NewController(
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
		)
		if err := controller.SetServerFactory(relayprocess.Factory(executable)); err != nil {
			a.lanShare = relayclient.Unavailable(err.Error())
		} else {
			a.lanShare = relayclient.NewLocal(controller)
		}
	}
	a.relayCheck = func(ctx context.Context, code relay.ShareCode) ([]string, error) {
		return relay.FormatReport(relay.Diagnose(ctx, code, relay.DiagnoseOptions{})), nil
	}
	a.lanShareUI.results = make(chan lanShareResult, 4)
	a.setupLANDiscovery()
}

func (a *app) relayConnector() vpn.Registration {
	return vpn.Registration{Protocol: model.ProtocolLANRelay, Connect: relayprocess.NewConnector(a.relayComponentPath(), a.saveRelaySnapshot)}
}

func (a *app) relayComponentPath() string {
	if a.relayExecutable != "" {
		return a.relayExecutable
	}
	return relayprocess.FindExecutable()
}
