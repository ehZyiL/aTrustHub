package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/cleanup/taskio"
	"github.com/ehzyil/connect-hub/internal/components"
)

func TestSelectionRejectsChangedAndDuplicateTargets(t *testing.T) {
	f := Finding{ID: "svc:fixture", Action: ActionDeleteService, Params: map[string]interface{}{"name": "fixture"}}
	old := &Plan{Findings: []Finding{f}}
	fresh := &Plan{Findings: []Finding{f}}
	if p, err := selectCurrentFindings(old, fresh, []string{f.ID}); err != nil || len(p.Findings) != 1 || !p.Findings[0].Selected {
		t.Fatalf("selection %v %v", p, err)
	}
	if _, err := selectCurrentFindings(old, fresh, []string{f.ID, f.ID}); err == nil {
		t.Fatal("duplicate accepted")
	}
	fresh.Findings[0].Params = map[string]interface{}{"name": "another"}
	if _, err := selectCurrentFindings(old, fresh, []string{f.ID}); err == nil {
		t.Fatal("modified target accepted")
	}
	if _, err := selectCurrentFindings(old, &Plan{}, []string{f.ID}); err == nil {
		t.Fatal("stale target accepted")
	}
}

func TestRecoveryReportsInterruptedMutationWithoutRetry(t *testing.T) {
	root := t.TempDir()
	old, err := taskio.NewDir(root)
	if err != nil {
		t.Fatal(err)
	}
	current, err := taskio.NewDir(root)
	if err != nil {
		t.Fatal(err)
	}
	req := contract.Request{Request: components.Request{Version: components.Version, InstanceID: "old", RequestID: "task", Operation: contract.Apply, Deadline: time.Now().Add(time.Minute)}}
	if err = taskio.Write(old, "request.json", req); err != nil {
		t.Fatal(err)
	}
	var logs []string
	if err = reportInterruptedTasks(context.Background(), current, func(s string, u contract.Update) error { logs = append(logs, s); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "未确认完成") {
		t.Fatalf("interrupted task hidden: %v", logs)
	}
	if _, err = os.Stat(old); err != nil {
		t.Fatal("recovery deleted original task", err)
	}
}

func TestCheckpointStopsOnCancelAndJournalFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(checkpoint(ctx, nil, "x"), context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	rw, err := NewReportWriter(filepath.Join(t.TempDir(), "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err = checkpoint(context.Background(), rw, "target"); err != nil {
		t.Fatal(err)
	}
	if err = rw.Close(); err != nil {
		t.Fatal(err)
	}
	if checkpoint(context.Background(), rw, "next") == nil {
		t.Fatal("operation allowed without durable journal")
	}
}

func TestRestoreValidationRejectsTraversalAndCorruption(t *testing.T) {
	dir := t.TempDir()
	if validateRestore(dir, &BackupManifest{Registry: []RegistryBackupItem{{BackupFile: "../outside.reg"}}}) == nil {
		t.Fatal("traversal accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "payload"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if validateRestore(dir, &BackupManifest{Files: []FileBackupItem{{BackupPath: "payload", OriginalPath: filepath.Join(dir, "target"), SHA256: "bad"}}}) == nil {
		t.Fatal("corrupted backup accepted")
	}
}
