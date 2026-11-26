//go:build windows

package service

import "testing"

func TestMutationLockExcludesConcurrentAndAllowsRestart(t *testing.T) {
	root := t.TempDir()
	unlock, err := lockMutations(root)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := lockMutations(root); err == nil {
		other()
		unlock()
		t.Fatal("concurrent mutation accepted")
	}
	unlock()
	unlock, err = lockMutations(root)
	if err != nil {
		t.Fatal("lock survived task exit", err)
	}
	unlock()
}
