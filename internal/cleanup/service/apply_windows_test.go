//go:build windows

package service

import "testing"

func TestKillProcessAlreadyExited(t *testing.T) {
	// A deliberately absent name; this test never targets a real application.
	status, message := executeKillProcess(Finding{Params: map[string]interface{}{"image": "connect-hub-absent-fixture-9f7491.exe"}})
	if status != StatusSkipped {
		t.Fatalf("already exited process: %s %s", status, message)
	}
}
