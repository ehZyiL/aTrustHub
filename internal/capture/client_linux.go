package capture

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

var ErrHelperUnavailable = errors.New("按软件接管助手未运行，请安装或启动 Linux 辅助服务")
var ErrHelperIncompatible = errors.New("辅助服务与当前应用版本不匹配，请更新辅助服务")

type controlClient struct {
	conn   *net.UnixConn
	reader *bufio.Reader
	token  string
	mu     sync.Mutex
}

func dialControl(ctx context.Context, path string, expectedUID uint32) (*controlClient, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrHelperUnavailable
	}
	conn := c.(*net.UnixConn)
	cred, err := peerCredentials(conn)
	if err != nil || cred.Uid != expectedUID {
		conn.Close()
		return nil, errors.New("capture: unexpected helper identity")
	}
	client := &controlClient{conn: conn, reader: bufio.NewReaderSize(conn, maxFrame)}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	var hello frame
	if err := readFrame(client.reader, &hello); err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if hello.Version != ProtocolVersion || hello.Type != "hello" || len(hello.Token) != 64 {
		conn.Close()
		return nil, ErrHelperIncompatible
	}
	client.token = hello.Token
	return client, nil
}

func (c *controlClient) call(ctx context.Context, req frame) (frame, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var res frame
	if err := ctx.Err(); err != nil {
		return res, err
	}
	// Include rollback in the response budget: attach may spend 20 seconds
	// installing and another 15 seconds recovering its journal.
	budget := 30 * time.Second
	if req.Type == "attach" || req.Type == "system_start" || req.Type == "system_sync" {
		budget = 40 * time.Second
	}
	deadline := time.Now().Add(budget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.conn.SetDeadline(deadline)
	// Cancelling a pending request invalidates the whole lease, rather than
	// leaving a late response to be mistaken for the next request.
	stop := context.AfterFunc(ctx, func() { c.conn.Close() })
	defer stop()
	req.Version, req.Token = ProtocolVersion, c.token
	if err := writeFrame(c.conn, req); err != nil {
		return res, err
	}
	if err := readFrame(c.reader, &res); err != nil {
		return res, err
	}
	if res.Version != ProtocolVersion || res.Type != req.Type {
		_ = c.conn.Close()
		return res, errors.New("capture: invalid helper response")
	}
	if res.Error != "" {
		return res, errors.New(res.Error)
	}
	return res, nil
}

// HelperAvailable performs a bounded authenticated handshake without changing
// any system state. Installation is intentionally separate from app startup.
func HelperAvailable(ctx context.Context) error {
	c, err := dialControl(ctx, SocketPath(os.Getuid()), 0)
	if err == nil {
		c.conn.Close()
	}
	return err
}
