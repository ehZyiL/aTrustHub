package wincapture

import (
	"errors"
	"slices"
	"sort"
)

// dnsPolicy publishes the union of active scopes in one owned NRPT rule.
// apply compares the current OS value with before, accepts already-after as an
// idempotent retry, and refuses to overwrite external changes.
type dnsPolicy struct {
	scopes map[string][]string
	apply  func(before, after []string) error
	dirty  bool
}

func (p *dnsPolicy) domains(except string, extra []string) []string {
	set := map[string]bool{}
	for id, domains := range p.scopes {
		if id == except {
			continue
		}
		for _, domain := range domains {
			set[domain] = true
		}
	}
	for _, domain := range extra {
		set[domain] = true
	}
	out := make([]string, 0, len(set))
	for domain := range set {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

func (p *dnsPolicy) acquire(id string, domains []string) (func() error, error) {
	if p.dirty {
		return nil, errors.New("DNS 策略尚未完成回滚或清理")
	}
	if p.scopes == nil {
		p.scopes = map[string][]string{}
	}
	if _, ok := p.scopes[id]; ok {
		return nil, errors.New("重复 DNS 接管作用域")
	}
	before, after := p.domains("", nil), p.domains(id, domains)
	if len(after) > 256 {
		return nil, errors.New("共享 DNS 接管后缀超过 256 个")
	}
	if !slices.Equal(before, after) {
		if err := p.apply(before, after); err != nil {
			p.dirty = true
			rollback := func() error {
				if !p.dirty {
					return nil
				}
				if err := p.apply(after, before); err != nil {
					return err
				}
				p.dirty = false
				return nil
			}
			if rollbackErr := rollback(); rollbackErr != nil {
				return rollback, errors.Join(err, rollbackErr)
			}
			return nil, err
		}
	}
	p.scopes[id] = slices.Clone(domains)
	released := false
	return func() error {
		if released {
			return nil
		}
		before, after := p.domains("", nil), p.domains(id, nil)
		if !slices.Equal(before, after) {
			if err := p.apply(before, after); err != nil {
				p.dirty = true
				return err
			}
		}
		delete(p.scopes, id)
		p.dirty, released = false, true
		return nil
	}, nil
}
