package wincapture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Only the subprocess mode runs user code; Prepare reserves an empty job.
// The loopback socket is its first observable action and needs no VPN account.
func TestWindowsProcessFixture(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-3] != "--capture-fixture" {
		return
	}
	address, role := os.Args[len(os.Args)-2], os.Args[len(os.Args)-1]
	if role == "parent" || role == "parent-exit" {
		exe, _ := os.Executable()
		child := exec.Command(exe, "-test.run=^TestWindowsProcessFixture$", "--", "--capture-fixture", address, "child")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if role == "parent" {
			defer func() { _ = child.Wait() }()
		} else {
			_ = child.Process.Release()
		}
	}
	conn, err := net.DialTimeout("tcp4", address, 5*time.Second)
	if err != nil {
		os.Exit(3)
	}
	defer conn.Close()
	identity, err := processIdentity(windows.CurrentProcess(), uint32(os.Getpid()))
	if err != nil {
		os.Exit(4)
	}
	_ = json.NewEncoder(conn).Encode(identity)
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	_, _ = bufio.NewReader(conn).ReadByte()
}

func TestWindowsChildrenOutliveRoot(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("Run tests as an ordinary user")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	exe, _ := os.Executable()
	p, err := Prepare(ctx, Program{Executable: exe, Args: []string{"-test.run=^TestWindowsProcessFixture$", "--", "--capture-fixture", listener.Addr().String(), "parent-exit"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err = p.Launch(); err != nil {
		t.Fatal(err)
	}
	root, err := windows.OpenProcess(windows.SYNCHRONIZE, false, p.Identity().PID)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(root)
	var parentConn, childConn net.Conn
	defer func() {
		if parentConn != nil {
			parentConn.Close()
		}
		if childConn != nil {
			childConn.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var identity Identity
		if err := json.NewDecoder(conn).Decode(&identity); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		if identity.PID == p.Identity().PID {
			parentConn = conn
		} else {
			childConn = conn
		}
	}
	if parentConn == nil || childConn == nil {
		t.Fatal("missing root or child connection")
	}
	_, _ = parentConn.Write([]byte{1})
	state, err := windows.WaitForSingleObject(root, 5000)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatal("root failed to exit", err)
	}
	select {
	case <-p.Done():
		t.Fatal("capture stopped while a child was still alive")
	case <-time.After(500 * time.Millisecond):
	}
	_, _ = childConn.Write([]byte{1})
	select {
	case <-p.Done():
		if err := p.Err(); err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("capture did not finish after last child exited")
	}
}

func TestWindowsLaunchBarrierChildrenAndDetach(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("Run this test as an ordinary user, not as administrator")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	exe, _ := os.Executable()
	p, err := Prepare(ctx, Program{Executable: exe, Args: []string{"-test.run=^TestWindowsProcessFixture$", "--", "--capture-fixture", listener.Addr().String(), "parent"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	tcpListener := listener.(*net.TCPListener)
	if p.PID() != 0 {
		t.Fatal("preparation created a process before helper acknowledgement")
	}
	if err := requireEmptyJob(windows.Handle(p.JobHandle())); err != nil {
		t.Fatal("prepared job already contains a process", err)
	}
	_ = tcpListener.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if c, err := listener.Accept(); err == nil {
		c.Close()
		t.Fatal("software ran before release")
	} else if e, ok := err.(net.Error); !ok || !e.Timeout() {
		t.Fatal(err)
	}
	if err := p.Launch(); err != nil {
		t.Fatal(err)
	}
	if err := p.Launch(); err == nil {
		t.Fatal("launched the same project twice")
	}
	if err := requireEmptyJob(windows.Handle(p.JobHandle())); err == nil {
		t.Fatal("used job accepted as a new capture reservation")
	}
	_ = tcpListener.SetDeadline(time.Now().Add(5 * time.Second))
	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	var identities []Identity
	for i := 0; i < 2; i++ {
		c, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var identity Identity
		if err := json.NewDecoder(c).Decode(&identity); err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity)
		member, err := p.Contains(identity)
		if err != nil || !member {
			t.Fatalf("root/child not in job: %+v %v", identity, err)
		}
		source := netip.MustParseAddrPort(c.RemoteAddr().String())
		destination := netip.MustParseAddrPort(c.LocalAddr().String())
		owner, err := LookupTCP(ctx, Tuple{source, destination})
		if err != nil {
			t.Fatal(err)
		}
		if owner.Identity != identity {
			owner.Close()
			t.Fatal("socket identity differs")
		}
		owner.Close()
		wrong := identity
		wrong.Created++
		if yes, err := p.Contains(wrong); err != nil || yes {
			t.Fatal("accepted stale creation time")
		}
	}
	self, _ := processIdentity(windows.CurrentProcess(), uint32(os.Getpid()))
	if member, err := p.Contains(self); err != nil || member {
		t.Fatalf("unselected process matched: %v %v", member, err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	for _, identity := range identities {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, identity.PID)
		if err != nil {
			t.Fatal("detach terminated an application", err)
		}
		state, err := windows.WaitForSingleObject(h, 0)
		windows.CloseHandle(h)
		if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
			t.Fatal("application exited on detach")
		}
	}
	for _, c := range conns {
		_, _ = c.Write([]byte{1})
	}
}

func TestWindowsCancelledLaunchCreatesNoProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exe, _ := os.Executable()
	p, err := Prepare(ctx, Program{Executable: exe, Args: []string{"-test.run=^TestWindowsProcessFixture$"}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cancel()
	if err := p.Launch(); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled launch proceeded", err)
	}
	if p.PID() != 0 {
		t.Fatal("cancelled launch created a process")
	}
	if err := requireEmptyJob(windows.Handle(p.JobHandle())); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Launch(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("closed reservation was launched", err)
	}
}
