package desktop

import (
	"github.com/ehzyil/connect-hub/internal/model"
)

// saveConfig writes the in-memory configuration and tells the manager.
func (a *app) saveConfig() error {
	if err := a.store.Save(); err != nil {
		return err
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	return nil
}

// setConfig publishes a new configuration. Every writer must go through it so a
// background reader can take a consistent copy instead of racing a whole-struct
// reassignment.
func (a *app) setConfig(cfg model.Config) {
	a.cfgMu.Lock()
	a.cfg = cfg
	a.cfgMu.Unlock()
}

// requestConfigReload tells the UI thread that the persisted configuration
// changed and asks for a repaint. Background code calls this instead of writing
// a.cfg: the UI thread owns that struct, and every reader of it (labels,
// panels, the whole render pass) would otherwise race a background write.
func (a *app) requestConfigReload() {
	a.cfgReload.Store(true)
	a.invalidate()
}

// applyPendingConfigReload runs on the UI thread before anything renders from
// a.cfg. It re-reads the Store at that moment rather than accepting a copy
// captured earlier, so a stale notification can never roll back a newer edit.
func (a *app) applyPendingConfigReload() {
	if !a.cfgReload.Swap(false) {
		return
	}
	if a.store == nil {
		return
	}
	next := a.store.Config()
	a.setConfig(next)
	if a.mgr != nil {
		a.mgr.Apply(next)
	}
}

// configForBackground returns a copy for goroutines that are not the UI thread.
// It runs at most a few times per second, so the copy is cheap next to the probe
// or dial it precedes.
func (a *app) configForBackground() model.Config {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.cfg.Clone()
}

// localAppIDsForBackground returns just the local-app IDs. The state ticker asks
// for them once a second, and cloning the whole configuration (access points,
// route policies, DNS bindings, every argument list) to read a handful of IDs is
// pure garbage — worse, that cost grows with the user's configuration, not with
// the work actually done.
func (a *app) localAppIDsForBackground() []string {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	ids := make([]string, len(a.cfg.LocalApps))
	for i := range a.cfg.LocalApps {
		ids[i] = a.cfg.LocalApps[i].ID
	}
	return ids
}

// mutateConfig edits the in-memory configuration under the write lock. It is for
// the settings the app changes outside Store.Update (auto restore intent).
func (a *app) mutateConfig(fn func(*model.Config)) {
	a.cfgMu.Lock()
	fn(&a.cfg)
	a.cfgMu.Unlock()
}
