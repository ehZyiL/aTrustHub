package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/qy/easyconnect/internal/wincapture"
)

func main() {
	pipe := flag.String("pipe", "", "desktop pipe session")
	watchdog := flag.String("watchdog", "", "network recovery session")
	parent := flag.Uint("parent", 0, "expected parent process ID")
	created := flag.Uint64("created", 0, "expected parent creation time")
	flag.Parse()
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
