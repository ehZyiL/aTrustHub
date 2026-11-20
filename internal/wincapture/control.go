package wincapture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/qy/easyconnect/internal/workeripc"
)

type controlTransport interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

type Session struct {
	runtime   *Session
	id        string
	gate      chan struct{}
	file      controlTransport
	reader    *bufio.Reader
	prefix    string
	done      chan struct{}
	once      sync.Once
	closeOnce sync.Once
	closeErr  error
	errMu     sync.Mutex
	err       error
}

func newSession(conn controlTransport) *Session {
	return &Session{gate: make(chan struct{}, 1), file: conn, reader: bufio.NewReaderSize(conn, maxFrame), done: make(chan struct{})}
}

func (s *Session) Prefix() string        { return s.prefix }
func (s *Session) Done() <-chan struct{} { return s.done }
func (s *Session) Err() error {
	s.errMu.Lock()
	err := s.err
	s.errMu.Unlock()
	if s.runtime != nil {
		return errors.Join(err, s.runtime.Err())
	}
	return err
}

func logicalSession(runtime *Session, id, prefix string) *Session {
	s := &Session{runtime: runtime, id: id, prefix: prefix, done: make(chan struct{})}
	go func() {
		select {
		case <-runtime.Done():
			s.fail(runtime.Err())
		case <-s.Done():
		}
	}()
	return s
}
func (s *Session) fail(err error) {
	s.once.Do(func() {
		s.errMu.Lock()
		s.err = err
		s.errMu.Unlock()
		if s.file != nil {
			_ = s.file.Close()
		}
		close(s.done)
	})
}

func (s *Session) request(ctx context.Context, req frame) (frame, error) {
	if s.runtime != nil {
		select {
		case <-s.done:
			return frame{}, errors.Join(os.ErrClosed, s.Err())
		default:
		}
		req.Session = s.id
		return s.runtime.requestScoped(ctx, req, s)
	}
	return s.requestScoped(ctx, req, nil)
}

func (s *Session) requestScoped(ctx context.Context, req frame, scope *Session) (frame, error) {
	select {
	case <-ctx.Done():
		return frame{}, ctx.Err()
	case <-s.done:
		return frame{}, errors.Join(os.ErrClosed, s.Err())
	case s.gate <- struct{}{}:
	}
	defer func() { <-s.gate }()
	if scope != nil {
		select {
		case <-scope.done:
			return frame{}, errors.Join(os.ErrClosed, scope.Err())
		default:
		}
	}
	select {
	case <-s.done:
		return frame{}, errors.Join(os.ErrClosed, s.Err())
	default:
	}
	if err := ctx.Err(); err != nil {
		return frame{}, err
	}
	timeout := 20 * time.Second
	if req.Type == "configure" || req.Type == "register" || req.Type == "attach" || req.Type == "unregister" {
		timeout = 60 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if req.Type == "configure" {
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
	}
	if err := s.file.SetDeadline(deadline); err != nil {
		err = fmt.Errorf("设置网络助手 %s 请求超时：%w", req.Type, err)
		s.fail(err)
		return frame{}, err
	}
	// Configure has no other users and can abort the transport immediately.
	// Once a shared request is sent, consume its bounded reply even if its
	// caller cancels. In particular Attach returns a detach closure so the
	// cancelled launcher can roll back without ending other applications.
	stop := func() bool { return true }
	if req.Type == "configure" {
		stop = context.AfterFunc(ctx, func() { s.fail(ctx.Err()) })
	}
	defer stop()
	if err := writeFrame(s.file, req); err != nil {
		err = fmt.Errorf("Windows 网络助手控制连接已关闭（发送 %s）", req.Type)
		s.fail(err)
		return frame{}, err
	}
	var reply frame
	if err := readFrame(s.reader, &reply); err != nil {
		err = fmt.Errorf("Windows 网络助手未及时响应或消息无效，接管已停止（等待 %s）", req.Type)
		s.fail(err)
		return frame{}, err
	}
	if req.Type == "configure" && (!stop() || ctx.Err() != nil) {
		s.fail(ctx.Err())
		return frame{}, ctx.Err()
	}
	if reply.Type == "error" && reply.Error != "" {
		return frame{}, errors.New(reply.Error)
	}
	if reply.Type != "ok" || reply.Error != "" {
		err := errors.New("Windows 网络助手应答类型无效")
		s.fail(err)
		return frame{}, err
	}
	return reply, nil
}

func (s *Session) Publish(ctx context.Context, aliases []workeripc.DNSAlias) error {
	_, err := s.request(ctx, frame{Type: "publish", Aliases: aliases})
	return err
}

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		if s.runtime != nil {
			// Revoke queued requests before releasing the transport gate after
			// unregister. A late publish cannot reactivate a retired scope.
			s.fail(nil)
			_, s.closeErr = s.runtime.request(context.Background(), frame{Type: "unregister", Session: s.id})
			s.errMu.Lock()
			s.err = s.closeErr
			s.errMu.Unlock()
			return
		}
		_, s.closeErr = s.request(context.Background(), frame{Type: "close"})
		s.fail(s.closeErr)
	})
	return s.closeErr
}
