package vpn

import (
	session "github.com/ehzyil/connect-hub/internal/vpn/contract"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
)

func appsFromZJU(in []atrustclient.App) []App {
	out := make([]App, 0, len(in))
	for _, app := range in {
		a := App{
			ID:            app.ID,
			Name:          app.Name,
			Description:   app.Description,
			AccessModel:   app.AccessModel,
			SubModel:      app.SubModel,
			GroupName:     app.GroupName,
			NodeGroupID:   app.NodeGroupID,
			NodeGroupName: app.NodeGroupName,
			IconPath:      app.IconPath,
			AppAddress:    app.AppAddress,
			AccessAddress: app.AccessAddress,
			AccessEntry:   app.AccessEntry,
		}
		for _, addr := range app.Addresses {
			a.Addresses = append(a.Addresses, AppAddress{
				Protocol: addr.Protocol,
				Host:     addr.Host,
				Port:     addr.Port,
			})
		}
		out = append(out, a)
	}
	return out
}

type App = session.App

type AppAddress = session.AppAddress
