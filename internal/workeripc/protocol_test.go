package workeripc

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkerProtocolContract(t *testing.T) {
	hub, err := os.ReadFile("protocol.go")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := os.ReadFile(filepath.Join("..", "..", "third_party", "zju-connect", "internal", "desktop", "protocol.go"))
	if err != nil {
		t.Fatal(err)
	}
	normalize := func(b []byte) []byte {
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		return bytes.ReplaceAll(b, []byte("package desktop"), []byte("package workeripc"))
	}
	if !bytes.Equal(normalize(hub), normalize(worker)) {
		t.Fatal("Hub/worker protocol contract differs")
	}
	if Version != 7 {
		t.Fatalf("resource attribution and flow preparation require protocol v7, got %d", Version)
	}
}
