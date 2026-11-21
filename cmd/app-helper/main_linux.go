package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ehZyiL/connect-hub/internal/capture"
)

func run() error {
	uid := flag.Int("uid", -1, "authorized desktop user UID")
	recoverOnly := flag.Bool("recover", false, "recover owned resources and exit")
	protocolVersion := flag.Bool("protocol-version", false, "print the capture helper protocol version")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected helper arguments")
	}
	if *protocolVersion {
		fmt.Println(capture.ProtocolVersion)
		return nil
	}
	s, err := capture.NewService(*uid)
	if err != nil {
		return err
	}
	if *recoverOnly {
		defer s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		return s.DrainAliases(ctx)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	err = s.Serve(ctx)
	closeErr := s.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
