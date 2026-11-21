package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/qy/easyconnect/internal/wincapture"
	"golang.org/x/sys/windows"
)

func main() {
	pipe := flag.String("pipe", "", "desktop pipe session")
	watchdog := flag.String("watchdog", "", "network recovery session")
	protocolVersion := flag.Bool("protocol-version", false, "print the capture helper protocol version")
	parent := flag.Uint("parent", 0, "expected parent process ID")
	created := flag.Uint64("created", 0, "expected parent creation time")
	flag.Parse()
	if len(os.Args) == 1 {
		explainManualLaunch()
		os.Exit(2)
	}
	if *protocolVersion {
		if flag.NArg() != 0 || *pipe != "" || *watchdog != "" || *parent != 0 || *created != 0 {
			os.Exit(2)
		}
		fmt.Println(wincapture.ProtocolVersion)
		return
	}
	if flag.NArg() != 0 || (*pipe == "") == (*watchdog == "") || uint64(*parent) > 0xffffffff {
		os.Exit(2)
	}
	identity := wincapture.Identity{PID: uint32(*parent), Created: *created}
	var err error
	if *watchdog != "" {
		err = wincapture.RunWatchdog(context.Background(), *watchdog, identity)
	} else {
		err = wincapture.RunHelper(context.Background(), *pipe, identity)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Windows capture helper stopped")
		os.Exit(1)
	}
}

// explainManualLaunch answers a user who double-clicked the helper in core/.
// Without it the elevated-only helper exits silently with no window at all.
func explainManualLaunch() {
	text, _ := windows.UTF16PtrFromString("此程序由 EasyConnect Hub 自动启动，请勿手动运行。\n\n请回到程序目录双击 easyconnect-hub.exe。")
	caption, _ := windows.UTF16PtrFromString("EasyConnect Hub")
	_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONINFORMATION|windows.MB_SETFOREGROUND)
}
