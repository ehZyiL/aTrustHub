//go:build !windows

package main

import (
	"github.com/egoist/mygo/ui"

	"github.com/ehzyil/connect-hub/internal/relay"
)

// lanShareFirewallView shows the platform guidance only: this build does not
// modify any firewall rule on macOS or Linux.
func (a *app) lanShareFirewallView(c *ui.Context, view relay.View) {
	if view.State != relay.StateRunning {
		return
	}
	info := relay.FirewallInfo()
	t := c.Theme()
	for _, line := range info.Lines {
		ui.Text(c, line).FontSize(11).TextColor(t.TextMuted).Wrap()
	}
}

// cleanupLanShareFirewall has nothing to remove where no rule is created.
func (a *app) cleanupLanShareFirewall(keepPort int) {}

// allowLanShareFirewall and removeLanShareFirewall are not reachable here; they
// exist so platform-neutral code can reference them without build tags.
func (a *app) allowLanShareFirewall(view relay.View) {}

func (a *app) removeLanShareFirewall(port int) {}
