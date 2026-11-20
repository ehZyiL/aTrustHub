package wincapture

import "errors"

type sharedRule struct {
	refs    int
	undo    func() error
	pending bool
}

// Control operations are serialized by the helper. Shared routes have one OS
// owner even when several gateway scopes need exactly the same prefix.
type sharedRules map[string]*sharedRule

func (s sharedRules) acquire(key string, install func() (func() error, error)) (func() error, error) {
	r := s[key]
	if r != nil && r.pending {
		return nil, errors.New("共享网络规则正在等待清理")
	}
	if r == nil {
		undo, err := install()
		if err != nil {
			return undo, err
		}
		r = &sharedRule{undo: undo}
		s[key] = r
	}
	r.refs++
	released := false
	return func() error {
		if released {
			return nil
		}
		if r.refs == 1 {
			if err := r.undo(); err != nil {
				r.pending = true
				return err
			}
			delete(s, key)
		}
		r.refs--
		released = true
		return nil
	}, nil
}
