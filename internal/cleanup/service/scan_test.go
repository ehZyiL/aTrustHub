//go:build windows

package service

import (
	"context"
	"errors"
	"testing"
)

func TestCanceledScanDoesNotStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := Scan(ScanOptions{Context: ctx}); p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled scan returned %v %v", p, err)
	}
}

func TestScanExecution(t *testing.T) {
	plan, err := Scan(ScanOptions{})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if plan == nil {
		t.Fatalf("Expected non-nil plan")
	}

	t.Logf("Scan completed: version=%d, elevated=%v, installedCount=%d, findingsCount=%d",
		plan.Version, plan.Elevated, len(plan.Installed), len(plan.Findings))

	for i, f := range plan.Findings {
		if f.ID == "" {
			t.Errorf("Finding #%d has empty ID", i)
		}
		if f.Action == "" {
			t.Errorf("Finding %s has empty Action", f.ID)
		}
	}
}
