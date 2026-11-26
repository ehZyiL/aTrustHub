//go:build windows

package taskio

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestTaskDirectoryHasProtectedUserACL(t *testing.T) {
	dir, err := NewDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	if !strings.HasPrefix(sddl, "D:P") || strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;BU)") || strings.Contains(sddl, ";;;AU)") {
		t.Fatalf("task directory exposes inherited or broad access: %s", sddl)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sddl, u.User.Sid.String()) {
		t.Fatalf("initiating user missing from ACL: %s", sddl)
	}
}

func TestMailboxRetriesTransientSharingViolation(t *testing.T) {
	dir, err := NewDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = Write(dir, "request.json", map[string]string{"value": "ready"}); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(filepath.Join(dir, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { time.Sleep(30 * time.Millisecond); windows.CloseHandle(h); close(done) }()
	var value map[string]string
	err = Read(dir, "request.json", &value)
	<-done
	if err != nil || value["value"] != "ready" {
		t.Fatalf("transient sharing violation was fatal: %v %v", value, err)
	}
	start := time.Now()
	err = retrySharing(func() error { return windows.ERROR_SHARING_VIOLATION })
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("sharing retry is unbounded: %v %s", err, time.Since(start))
	}
	if retrySharing(func() error { return windows.ERROR_ACCESS_DENIED }) != windows.ERROR_ACCESS_DENIED {
		t.Fatal("permission error was hidden")
	}
}
