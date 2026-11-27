package main

import (
	"fmt"
	"os"

	"github.com/ehzyil/connect-hub/internal/relay/process"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--protocol-version" {
		_, _ = fmt.Fprintln(os.Stdout, process.ProtocolVersionString())
		return
	}
	if err := process.ChildMain(os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
