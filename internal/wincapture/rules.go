package wincapture

import "errors"

// ruleSet owns only operations successfully installed by this session. Failed
// rollback entries stay owned for a later cleanup attempt; they are never
// discarded or treated as a successful stop. The helper serializes calls.
type ruleSet struct {
	install []func() (func() error, error)
	undo    []func() error
	active  bool
}

func (r *ruleSet) Enable() error {
	if r.active {
		return nil
	}
	if len(r.undo) != 0 {
		return errors.New("上次网络规则尚未清理完成，请重新连接")
	}
	for _, install := range r.install {
		undo, err := install()
		if undo != nil {
			r.undo = append(r.undo, undo)
		}
		if err != nil {
			return errors.Join(err, r.Disable())
		}
	}
	r.active = true
	return nil
}

func (r *ruleSet) Disable() error {
	r.active = false
	var failures []error
	var pending []func() error
	for i := len(r.undo) - 1; i >= 0; i-- {
		if err := r.undo[i](); err != nil {
			failures = append(failures, err)
			pending = append(pending, r.undo[i])
		}
	}
	// Preserve installation order so repeated cleanup still runs in reverse.
	r.undo = nil
	for i := len(pending) - 1; i >= 0; i-- {
		r.undo = append(r.undo, pending[i])
	}
	return errors.Join(failures...)
}
