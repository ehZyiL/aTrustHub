package vpn

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/ehzyil/connect-hub/internal/model"
)

// D2: a taken aggregate port is reported. The previous behaviour silently walked
// forward, which left the system proxy, the settings page and every configured
// tool pointing at a port that now belongs to another program.
func TestAggregatePortInUseIsReportedNotMoved(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	port := taken.Addr().(*net.TCPAddr).Port

	settings := model.DefaultSettings()
	settings.ListenHost = "127.0.0.1"
	settings.AggregatePort = port
	settings.AggregateEnabled = true

	m := NewManager(func(context.Context, model.AccessPoint, Credentials) (Session, error) {
		return nil, errors.New("not used")
	}, nil, nil, nil)
	defer m.Close()
	m.Apply(model.Config{Settings: settings})
	m.Start()

	endpoint := m.Aggregate()
	if endpoint.Running {
		t.Fatalf("aggregate started on %q although the configured port was taken", endpoint.Addr)
	}
	if endpoint.Addr != "" {
		t.Fatalf("aggregate reports an address while not running: %q", endpoint.Addr)
	}
	if !strings.Contains(endpoint.Error, strconv.Itoa(port)) {
		t.Fatalf("error does not name the configured port: %q", endpoint.Error)
	}
	// Running==false is exactly the discriminator: the old implementation walked
	// forward and reported Running on a different port instead of failing. Do not
	// assert that port+1 is free here — in an ephemeral range another process (or
	// another test) may hold it, which says nothing about this behaviour.
}

// The free-port path still works, and the reported address is exactly the
// configured one.
func TestAggregateUsesConfiguredPort(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	settings := model.DefaultSettings()
	settings.ListenHost = "127.0.0.1"
	settings.AggregatePort = port

	m := NewManager(func(context.Context, model.AccessPoint, Credentials) (Session, error) {
		return nil, errors.New("not used")
	}, nil, nil, nil)
	defer m.Close()
	m.Apply(model.Config{Settings: settings})
	m.Start()

	endpoint := m.Aggregate()
	want := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if !endpoint.Running || endpoint.Addr != want {
		t.Fatalf("aggregate = %+v, want %s", endpoint, want)
	}
}
