package process

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay"
)

// TestRelayResourceProfile is an opt-in comparison fixture for process-tree
// sampling. It uses a local echo source, never a VPN or system network setting.
func TestRelayResourceProfile(t *testing.T) {
	mode := strings.TrimSpace(os.Getenv("CONNECT_HUB_RELAY_PROFILE"))
	if mode == "" {
		t.Skip("set CONNECT_HUB_RELAY_PROFILE=inproc or sidecar to run the resource fixture")
	}
	if mode != "inproc" && mode != "sidecar" {
		t.Fatalf("unsupported relay profile mode %q", mode)
	}

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()

	source := newTestSource(echo.Addr().String())
	identity, err := relay.GenerateIdentity("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	opts := relay.ServerOptions{Identity: identity, Source: source, Token: "resource-profile-token-with-enough-entropy",
		ShareID: "resource-profile-share", ServerInstanceID: "resource-profile-instance", Port: 0}
	var server relay.ServerInstance
	if mode == "inproc" {
		server, err = relay.StartServer(opts)
	} else {
		server, err = Factory(os.Getenv("EASYCONNECT_RELAY"))(opts)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = server.Close(context.Background())
		_ = source.Close()
	}()

	code := relay.ShareCode{Version: 1, Host: "127.0.0.1", Port: server.Port(), ShareID: opts.ShareID,
		Token: opts.Token, Fingerprint: identity.Fingerprint}
	const workers = 4
	clients := make([]*relay.Client, 0, workers)
	conns := make([]net.Conn, 0, workers)
	for range workers {
		client, err := relay.NewClient(relay.ClientOptions{Code: code, Dial: relay.DirectDialer})
		if err != nil {
			t.Fatal(err)
		}
		state, token, err := client.Open(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		conn, err := client.Dial(context.Background(), token, state.Epoch, state.Revision, "10.1.2.3:443")
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		clients = append(clients, client)
		conns = append(conns, conn)
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
		for _, client := range clients {
			client.Close()
		}
	}()

	fmt.Fprintf(os.Stdout, "PROFILE_READY mode=%s pid=%d workers=%d\n", mode, os.Getpid(), workers)
	const duration = 20 * time.Second
	payload := bytes.Repeat([]byte("relay-profile-"), 1024)
	latencies := make([]time.Duration, 0, 4096)
	var latencyMu sync.Mutex
	var totalBytes atomic.Int64
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	var wg sync.WaitGroup
	for _, conn := range conns {
		conn := conn
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := make([]byte, len(payload))
			for ctx.Err() == nil {
				begin := time.Now()
				if _, err := io.Copy(conn, bytes.NewReader(payload)); err != nil {
					return
				}
				if _, err := io.ReadFull(conn, response); err != nil {
					return
				}
				elapsed := time.Since(begin)
				latencyMu.Lock()
				latencies = append(latencies, elapsed)
				latencyMu.Unlock()
				totalBytes.Add(int64(len(payload)))
			}
		}()
	}
	<-ctx.Done()
	cancel()
	for _, conn := range conns {
		_ = conn.Close()
	}
	wg.Wait()
	elapsed := time.Since(started).Seconds()
	if len(latencies) == 0 {
		t.Fatal("profile traffic completed no round trips")
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pick := func(p float64) float64 {
		i := int(float64(len(latencies)-1) * p)
		return float64(latencies[i]) / float64(time.Millisecond)
	}
	mbps := float64(totalBytes.Load()) / elapsed / (1024 * 1024)
	fmt.Printf("PROFILE_RESULT mode=%s samples=%d bytes=%d throughput_mib_s=%.3f p50_ms=%.3f p95_ms=%.3f\n",
		mode, len(latencies), totalBytes.Load(), mbps, pick(0.50), pick(0.95))
}
