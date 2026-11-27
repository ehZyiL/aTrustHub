package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRelayCommandConsoleHelper(t *testing.T) {
	if os.Getenv("CONNECT_HUB_TEST_NO_CONSOLE") != "1" {
		return
	}
	window, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetConsoleWindow").Call()
	if window != 0 {
		os.Exit(2)
	}
	fmt.Print(ProtocolVersion)
	os.Exit(0)
}

func TestRelayCommandsHaveNoConsoleAndKeepProtocolOutput(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, cmd := range []*exec.Cmd{
		newCommand(exe, "-test.run=^TestRelayCommandConsoleHelper$"),
		newCommandContext(ctx, exe, "-test.run=^TestRelayCommandConsoleHelper$"),
	} {
		cmd.Env = append(os.Environ(), "CONNECT_HUB_TEST_NO_CONSOLE=1")
		out, err := cmd.Output()
		if err != nil || strings.TrimSpace(string(out)) != ProtocolVersion {
			t.Fatalf("hidden child lost protocol output or inherited a console: %v", err)
		}
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if err := newCommandContext(canceled, exe).Run(); err != context.Canceled {
		t.Fatalf("command lost context cancellation: %v", err)
	}
}

func TestDiscoveryProcessDoesNotCreateConsole(t *testing.T) {
	r := NewDiscoveryRuntime(buildRelayChild(t), nil, nil, nil)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.Publisher().Close(ctx)
		_ = r.Browser().Shutdown()
	})
	if err := r.ensure(); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil || r.cmd.SysProcAttr == nil || !r.cmd.SysProcAttr.HideWindow || r.cmd.SysProcAttr.CreationFlags&0x08000000 == 0 {
		t.Fatal("discovery child can create a visible Windows console")
	}
}
