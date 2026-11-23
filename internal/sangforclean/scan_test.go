//go:build windows

package sangforclean

import (
	"testing"
)

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
