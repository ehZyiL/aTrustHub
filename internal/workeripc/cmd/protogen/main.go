// Command protogen makes the worker protocol a single source of truth.
//
// The worker (third_party/zju-connect/internal/desktop/protocol.go) and the desktop
// (aTrustHub/internal/workeripc/protocol.go) must be byte-identical apart from
// the package clause. Hand-copying that file is what produced "the two sides
// drifted and nobody noticed"; this tool copies it and rewrites only the one line
// that has to differ.
//
// Regenerate with:  go generate ./internal/workeripc
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	wantPackage = "package desktop"
	outPackage  = "package workeripc"
)

func main() {
	src := flag.String("src", "", "worker protocol.go path")
	out := flag.String("out", "", "destination protocol.go path")
	check := flag.Bool("check", false, "verify the destination is up to date instead of writing it")
	flag.Parse()
	if *src == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "protogen: -src and -out are required")
		os.Exit(2)
	}
	data, err := os.ReadFile(*src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "protogen: %v\n", err)
		os.Exit(1)
	}
	// Normalize line endings first: the two checkouts can disagree on CRLF, and a
	// mixed file would make the very diff gate this tool exists for unreadable.
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if !strings.HasPrefix(text, wantPackage) && !strings.Contains(text, "\n"+wantPackage) {
		fmt.Fprintf(os.Stderr, "protogen: %s does not start with %q\n", *src, wantPackage)
		os.Exit(1)
	}
	text = strings.Replace(text, wantPackage, outPackage, 1)

	if *check {
		current, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "protogen: %v\n", err)
			os.Exit(1)
		}
		if strings.ReplaceAll(string(current), "\r\n", "\n") != text {
			fmt.Fprintf(os.Stderr, "protogen: %s is stale; run: go generate ./internal/workeripc\n", *out)
			os.Exit(1)
		}
		fmt.Printf("protogen: %s is up to date\n", filepath.Base(*out))
		return
	}
	if err := os.WriteFile(*out, []byte(text), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "protogen: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("protogen: wrote %s from %s\n", filepath.Base(*out), filepath.Base(*src))
}
