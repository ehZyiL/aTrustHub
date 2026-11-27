package relay

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type startupTestServer struct {
	done    chan struct{}
	closing chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *startupTestServer) Port() int             { return 23456 }
func (s *startupTestServer) ActiveClients() int    { return 0 }
func (s *startupTestServer) Done() <-chan struct{} { return s.done }
func (s *startupTestServer) RevokeAll()            {}
func (s *startupTestServer) Close(context.Context) error {
	s.once.Do(func() {
		if s.closing != nil {
			close(s.closing)
			<-s.release
		}
		close(s.done)
	})
	return nil
}

func TestControllerStartupFailureCleansOutsideStateLock(t *testing.T) {
	for _, first := range []bool{true, false} {
		t.Run(map[bool]string{true: "enable", false: "restore"}[first], func(t *testing.T) {
			sink := newFakeSink("p1")
			c := NewController(newFakePersistence(), sink, loopbackNets(), nil, nil)
			failed := &startupTestServer{done: make(chan struct{}), closing: make(chan struct{}), release: make(chan struct{})}
			finish := sync.OnceFunc(func() { close(failed.release) })
			defer finish()
			var armed atomic.Bool
			if err := c.SetServerFactory(func(ServerOptions) (ServerInstance, error) {
				if armed.Load() {
					return failed, errors.New("injected factory failure")
				}
				return &startupTestServer{done: make(chan struct{})}, nil
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { finish(); _ = c.Shutdown(context.Background()) })
			if !first {
				if err := c.Enable(context.Background(), EnableOptions{PointID: "p1"}); err != nil {
					t.Fatal(err)
				}
				if err := c.Suspend(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			armed.Store(true)
			result := make(chan error, 1)
			go func() {
				if first {
					result <- c.Enable(context.Background(), EnableOptions{PointID: "p1"})
				} else {
					result <- c.Restore(context.Background())
				}
			}()
			awaitStartupTest(t, failed.closing)
			assertStartupViewResponsive(t, c)
			finish()
			if err := awaitStartupTest(t, result); err == nil {
				t.Fatal("startup failure was lost")
			}
			got := c.View()
			if (first && (got.State != StateOff || got.Enabled)) || (!first && (got.State != StateBlocked || !got.Enabled)) {
				t.Fatalf("startup failure changed lifecycle semantics: %+v", got)
			}
			select {
			case <-sink.currentSource("p1").Done():
			default:
				t.Fatal("failed startup source was retained")
			}
		})
	}
}

type startupTestSink struct {
	*fakeSink
	acquire func(context.Context)
}

func (s *startupTestSink) AcquireSource(ctx context.Context, id string) (Source, error) {
	s.acquire(ctx)
	return s.fakeSink.AcquireSource(ctx, id)
}

func awaitStartupTest[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("startup operation did not reach its checkpoint")
		var zero T
		return zero
	}
}

func assertStartupViewResponsive(t *testing.T, c *Controller) {
	t.Helper()
	view := make(chan View, 1)
	go func() { view <- c.View() }()
	select {
	case got := <-view:
		if got.State != StateStarting {
			t.Errorf("startup view state = %s", got.State)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Controller.View waited for startup I/O")
	}
}

func TestControllerStartupLeavesViewResponsive(t *testing.T) {
	for _, operation := range []string{"enable", "restore", "resume", "automatic"} {
		for _, stage := range []string{"source", "factory"} {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				entered, release := make(chan struct{}), make(chan struct{})
				finish := sync.OnceFunc(func() { close(release) })
				defer finish()
				var armed atomic.Bool
				block := func() {
					if armed.Load() {
						close(entered)
						<-release
					}
				}
				sink := &startupTestSink{fakeSink: newFakeSink("p1"), acquire: func(context.Context) {
					if stage == "source" {
						block()
					}
				}}
				c := NewController(newFakePersistence(), sink, loopbackNets(), nil, nil)
				t.Cleanup(func() { finish(); _ = c.Shutdown(context.Background()) })
				if err := c.SetServerFactory(func(ServerOptions) (ServerInstance, error) {
					if stage == "factory" {
						block()
					}
					return &startupTestServer{done: make(chan struct{})}, nil
				}); err != nil {
					t.Fatal(err)
				}
				if operation != "enable" {
					if err := c.Enable(context.Background(), EnableOptions{PointID: "p1"}); err != nil {
						t.Fatal(err)
					}
					if operation == "resume" {
						if err := c.PauseSharing(context.Background()); err != nil {
							t.Fatal(err)
						}
					} else if err := c.Suspend(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				armed.Store(true)
				result := make(chan error, 1)
				go func() {
					var err error
					switch operation {
					case "enable":
						err = c.Enable(context.Background(), EnableOptions{PointID: "p1"})
					case "resume":
						err = c.ResumeSharing(context.Background())
					case "restore":
						err = c.Restore(context.Background())
					case "automatic":
						c.opMu.Lock()
						c.reconcileTick(context.Background())
						c.opMu.Unlock()
					}
					result <- err
				}()
				awaitStartupTest(t, entered)
				assertStartupViewResponsive(t, c)
				// Preferences may change during startup; committing the listener
				// must preserve the newer preference rather than a stale snapshot.
				changed := make(chan error, 1)
				go func() { changed <- c.SetDiscovery(true, "new name") }()
				select {
				case err := <-changed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(200 * time.Millisecond):
					t.Error("preference update waited for startup I/O")
					finish()
					awaitStartupTest(t, changed)
				}
				finish()
				if err := awaitStartupTest(t, result); err != nil {
					t.Fatal(err)
				}
				if got := c.View(); got.State != StateRunning || !got.DiscoveryEnabled || got.DiscoveryName != "new name" {
					t.Fatalf("startup lost runtime or preferences: %+v", got)
				}
			})
		}
	}
}

func TestControllerCancelledStartupReclaimsLateResources(t *testing.T) {
	for _, stop := range []string{"disable", "shutdown"} {
		t.Run(stop, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			finish := sync.OnceFunc(func() { close(release) })
			defer finish()
			p, sink := newFakePersistence(), newFakeSink("p1")
			c := NewController(p, sink, loopbackNets(), nil, nil)
			server := &startupTestServer{done: make(chan struct{})}
			if err := c.SetServerFactory(func(ServerOptions) (ServerInstance, error) {
				close(entered)
				<-release // Some factories finish despite cancellation.
				return server, nil
			}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { finish(); _ = c.Shutdown(context.Background()) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- c.Enable(ctx, EnableOptions{PointID: "p1"}) }()
			awaitStartupTest(t, entered)
			assertStartupViewResponsive(t, c)
			cancel()
			stopped := make(chan error, 1)
			go func() {
				if stop == "disable" {
					stopped <- c.Disable(context.Background())
				} else {
					stopped <- c.Shutdown(context.Background())
				}
			}()
			finish()
			if err := awaitStartupTest(t, result); !errors.Is(err, context.Canceled) {
				t.Fatalf("enable returned %v", err)
			}
			if err := awaitStartupTest(t, stopped); err != nil {
				t.Fatal(err)
			}
			select {
			case <-server.Done():
			default:
				t.Error("late server was not closed")
			}
			select {
			case <-sink.currentSource("p1").Done():
			default:
				t.Error("late source was not closed")
			}
			if c.View().Enabled || p.secretCount() != 0 || c.runDone != nil || c.server != nil || c.source != nil {
				t.Fatal("cancelled first enable retained intent, secrets or runtime")
			}
		})
	}
}
