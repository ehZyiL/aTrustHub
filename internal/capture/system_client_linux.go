package capture

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/ehZyiL/connect-hub/internal/dnsmapping"
	"github.com/ehZyiL/connect-hub/internal/workeripc"
)

// SystemLease owns a single helper connection and all its system routes.
// The caller keeps it alive with Ping and calls Close even after a failed Start.
type SystemLease struct {
	client *controlClient
	path   string
}

func OpenSystem(ctx context.Context) (*SystemLease, error) {
	path := SocketPath(os.Getuid())
	client, err := dialControl(ctx, path, 0)
	if err != nil {
		return nil, err
	}
	return &SystemLease{client: client, path: path}, nil
}

func (l *SystemLease) Start(ctx context.Context, config SystemConfig) (SystemState, error) {
	return l.configure(ctx, "system_start", config)
}

func (l *SystemLease) Sync(ctx context.Context, config SystemConfig) (SystemState, error) {
	return l.configure(ctx, "system_sync", config)
}

func (l *SystemLease) configure(ctx context.Context, method string, config SystemConfig) (SystemState, error) {
	if err := config.validate(); err != nil {
		return SystemState{}, err
	}
	res, err := l.client.call(ctx, frame{Type: method, System: &config})
	if err != nil {
		return SystemState{}, err
	}
	if !res.Active || res.State == nil || res.State.Original.validate() != nil {
		return SystemState{}, errors.New("capture: invalid system TUN acknowledgement")
	}
	seen := make(map[netip.Prefix]bool)
	for _, resource := range config.Resources {
		if resource.Guard || len(resource.Domains) == 0 {
			continue
		}
		prefix, err := netip.ParsePrefix(res.State.Prefixes[resource.ID])
		if err != nil || !dnsmapping.ValidPrefix(prefix) || seen[prefix] {
			return SystemState{}, errors.New("capture: invalid system DNS pool acknowledgement")
		}
		seen[prefix] = true
	}
	if len(seen) != len(res.State.Prefixes) {
		return SystemState{}, errors.New("capture: unexpected system DNS pool acknowledgement")
	}
	return *res.State, nil
}

func (l *SystemLease) Publish(ctx context.Context, id string, aliases []workeripc.DNSAlias) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Once a publication starts, finish the acknowledged RPC even if its DNS
	// client goes away. Cancelling the RPC would tear down unrelated traffic.
	request, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
	defer cancel()
	_, err := l.client.call(request, frame{Type: "system_publish", ID: id, Mappings: aliases})
	return err
}

func (l *SystemLease) Ping(ctx context.Context) error {
	res, err := l.client.call(ctx, frame{Type: "system_ping"})
	if err == nil && !res.Active {
		return net.ErrClosed
	}
	return err
}

func (l *SystemLease) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 26*time.Second)
	_, err := l.client.call(ctx, frame{Type: "system_stop"})
	cancel()
	_ = l.client.conn.Close()
	if err == nil {
		return nil
	}
	// Disconnect triggers rollback in the helper. Confirm it through a new
	// connection, also covering a helper already restarted by systemd.
	ctx, cancel = context.WithTimeout(context.Background(), 26*time.Second)
	defer cancel()
	c, connectErr := dialControl(ctx, l.path, 0)
	if connectErr != nil {
		return errors.Join(err, connectErr)
	}
	defer c.conn.Close()
	_, err = c.call(ctx, frame{Type: "system_cleanup", ID: l.client.token})
	return err
}
