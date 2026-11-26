package contract

import (
	"github.com/ehzyil/connect-hub/internal/attribution"
)

// CloneInfo owns every mutable slice and map crossing a connector boundary.
func CloneInfo(in SessionInfo) SessionInfo {
	in.Resources = attribution.Clone(in.Resources)
	if in.Apps != nil {
		apps := make([]App, len(in.Apps))
		for i, app := range in.Apps {
			apps[i] = app
			apps[i].Addresses = append([]AppAddress(nil), app.Addresses...)
		}
		in.Apps = apps
	}
	in.NodeGroups = append([]string(nil), in.NodeGroups...)
	if in.BestNodes != nil {
		nodes := make(map[string]string, len(in.BestNodes))
		for key, value := range in.BestNodes {
			nodes[key] = value
		}
		in.BestNodes = nodes
	}
	return in
}
