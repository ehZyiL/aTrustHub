package localapps

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/proxy"
)

func TestForwardCountsStreamsAndPayload(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(c)
		c.Write(append([]byte("reply:"), b...))
	}()
	events := make(chan AccessEvent, 2)
	m := NewManager(nil, func(e AccessEvent) { events <- e })
	defer m.Close()
	p := forwardProfile()
	if err = m.Start(p, "", Connection{Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}}); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", m.View(p.ID).LocalAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(c, "query")
	c.(*net.TCPConn).CloseWrite()
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "reply:query" {
		t.Fatalf("%q %v", b, err)
	}
	m.Stop(p.ID)
	s := m.View(p.ID).Connections
	if s.Attempts != 1 || s.Opened != 1 || s.Failed != 0 || s.Active != 0 || s.Connecting != 0 || s.Sent != 5 || s.Received != 11 {
		t.Fatalf("counts: %+v", s)
	}
	e := <-events
	if e.Name != p.Name || e.Target != p.RemoteAddress || e.Result.Route != "unknown" {
		t.Fatalf("inferred unsupported route: %+v", e)
	}
}

func TestCaptureOldConnectionsDoNotAffectRestart(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()
	dials := make(chan DialFunc, 2)
	m.captureStart = func(_ context.Context, _ model.LocalApp, d DialFunc) (managedCapture, error) {
		dials <- d
		return &fakeCapture{done: make(chan struct{})}, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		t.Cleanup(func() { b.Close() })
		return a, nil
	}
	if err := m.StartCapture(captureProfile(t), dial, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	first := <-dials
	awaitView(t, m, func(v View) bool { return v.Running })
	c, err := first(context.Background(), "tcp", "10.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if m.View("ide").Connections.Active != 1 {
		t.Fatal("active connection missing")
	}
	m.Stop("ide")
	if err := m.StartCapture(captureProfile(t), dial, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	<-dials
	awaitView(t, m, func(v View) bool { return v.Running })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Close() }()
	}
	wg.Wait()
	if s := m.View("ide").Connections; s != (Connections{}) {
		t.Fatalf("old callbacks affected restart: %+v", s)
	}
}

func TestFailedDialsCountWithoutLeakingErrorText(t *testing.T) {
	events := make(chan AccessEvent, 1)
	m := NewManager(nil, func(e AccessEvent) { events <- e })
	defer m.Close()
	dials := make(chan DialFunc, 1)
	m.captureStart = func(_ context.Context, _ model.LocalApp, d DialFunc) (managedCapture, error) {
		dials <- d
		return &fakeCapture{done: make(chan struct{})}, nil
	}
	if err := m.StartCapture(captureProfile(t), func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("sensitive raw gateway data")
	}, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	dial := <-dials
	awaitView(t, m, func(v View) bool { return v.Running })
	if _, err := dial(context.Background(), "tcp", "10.0.0.1:443"); err == nil {
		t.Fatal("dial unexpectedly succeeded")
	}
	s := m.View("ide").Connections
	if s.Attempts != 1 || s.Failed != 1 || s.Active != 0 || s.Opened != 0 || s.Connecting != 0 {
		t.Fatal(s)
	}
	e := <-events
	if e.Result.Failure != "connect" || e.Result.Route != "unknown" {
		t.Fatal(e)
	}
}

func TestQuietStreamEventuallyRefreshesItsLastBytes(t *testing.T) {
	updates := make(chan struct{}, 16)
	m := NewManager(func() {
		select {
		case updates <- struct{}{}:
		default:
		}
	})
	defer m.Close()
	r := &run{view: View{ID: "quiet", Running: true}}
	m.runs[r.view.ID] = r
	m.trafficChanged(r, true)
	<-updates
	r.connections.received.Add(4)
	m.trafficChanged(r, false)
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("last byte count never repainted for idle stream")
	}
}

func TestManagedBrowserUsesObservedEntryAndSurvivesManagerClose(t *testing.T) {
	exe, ready, release := fakeBrowser(t)
	m := NewManager(nil)
	defer m.Close()
	p := model.LocalApp{ID: "web", Name: "web", PointID: "point", Mode: model.LocalAppBrowser, Executable: exe, URL: "https://portal.example/"}
	if err := m.Start(p, "", Connection{Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("fixture offline") }}); err != nil {
		t.Fatal(err)
	}
	profile := browserProfile(t, ready)
	b, _ := os.ReadFile(ready)
	var args []string
	json.Unmarshal(b, &args)
	address := ""
	for _, arg := range args {
		if a, ok := strings.CutPrefix(arg, "--proxy-server=socks5://"); ok {
			address = a
		}
	}
	d, err := proxy.NewSOCKSDialer(address, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := d.DialContext(context.Background(), "tcp", "10.0.0.1:443"); err == nil {
		c.Close()
		t.Fatal("offline dial succeeded")
	}
	waitUntil(t, func() bool { return m.View(p.ID).Connections.Failed == 1 })
	m.Close()
	if c, err := net.DialTimeout("tcp", address, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("browser proxy survived manager close")
	}
	if _, err := os.Stat(profile); err != nil {
		t.Fatal("manager terminated browser or removed its active profile")
	}
	os.WriteFile(release, nil, 0600)
	waitUntil(t, func() bool { _, err := os.Stat(profile); return os.IsNotExist(err) })
}
