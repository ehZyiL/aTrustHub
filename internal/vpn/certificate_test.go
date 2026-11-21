package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/workeripc"
)

func init() {
	mode := os.Getenv("EASYCONNECT_TEST_CERTIFICATE_WORKER")
	if mode == "" {
		return
	}
	input, err := io.ReadAll(os.Stdin)
	var request workeripc.Message
	if err != nil || json.Unmarshal(input, &request) != nil || request.Type != "certificate_probe" || request.Config != nil || request.Answer != "" || request.Address != "gateway.test:8443" {
		os.Exit(3)
	}
	if mode == "hang" {
		time.Sleep(10 * time.Second)
		os.Exit(4)
	}
	if mode == "old" {
		os.Exit(1)
	}
	reply := workeripc.Message{Version: workeripc.Version, Session: request.Session, Address: request.Address, Type: "certificate", Certificate: &workeripc.CertificateInfo{SHA256: strings.Repeat("a", 64), Subject: "CN=test", Issuer: "CN=test", NotBefore: 1, NotAfter: 2}}
	switch mode {
	case "session":
		reply.Session = "stale"
	case "address":
		reply.Address = "other.test:443"
	case "pin":
		reply.Certificate.SHA256 = "invalid"
	case "error":
		reply.Type, reply.Error = "error", "private upstream error"
	}
	_ = json.NewEncoder(os.Stdout).Encode(reply)
	os.Exit(0)
}

func TestCertificateProbeWorkerIPC(t *testing.T) {
	exe, _ := os.Executable()
	for _, mode := range []string{"ok", "session", "address", "pin", "error", "old", "hang"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("EASYCONNECT_TEST_CERTIFICATE_WORKER", mode)
			duration := 2 * time.Second
			if mode == "hang" {
				duration = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			info, err := probeGatewayCertificate(ctx, exe, "gateway.test", 8443)
			if mode == "ok" {
				if err != nil || info.SHA256 != strings.Repeat("a", 64) {
					t.Fatal(info, err)
				}
			} else if err == nil || info != nil {
				t.Fatal("invalid/cancelled observation accepted")
			}
			if mode == "hang" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("cancellation lost", err)
			}
			if err != nil && strings.Contains(err.Error(), "private") {
				t.Fatal("raw upstream error leaked")
			}
		})
	}
}
