//go:build !windows

package service

func lockMutations(string) (func(), error) { return nil, ErrUnsupported }
