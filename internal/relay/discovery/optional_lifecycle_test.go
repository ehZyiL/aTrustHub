package discovery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestPublisherRetiresBetweenUses(t *testing.T) {
	backend := newHubBackend(newHub())
	p := NewPublisher(PublisherOptions{Backend: backend})
	t.Cleanup(func() { _ = p.Close(context.Background()) })
	if p.done != nil {
		t.Fatal("constructor started a worker")
	}
	for i := 0; i < 10; i++ {
		p.Set(testAnnouncement(uint64(i+1), "共享"))
		waitFor(t, "published", func() bool { return p.Status().State == StatusPublished })
		p.mu.Lock()
		done := p.done
		p.mu.Unlock()
		p.Clear()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("clear left its worker alive")
		}
		if backend.liveCount() != 0 {
			t.Fatal("clear retained a registration")
		}
	}
}

func TestPublisherConcurrentClearSetAndClose(t *testing.T) {
	backend := newHubBackend(newHub())
	p := NewPublisher(PublisherOptions{Backend: backend})
	var wg sync.WaitGroup
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				p.Set(testAnnouncement(uint64(n*30+i+1), "共享"))
				p.Clear()
			}
		}(n)
	}
	wg.Wait()
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.Set(testAnnouncement(999, "关闭后"))
	if backend.liveCount() != 0 {
		t.Fatal("closed publisher retained a registration")
	}
}

type cancellingBrowseBackend struct {
	started chan struct{}
	closed  chan struct{}
}

func (b *cancellingBrowseBackend) Advertise(context.Context, Announcement) (Registration, error) {
	return nil, errors.New("unused")
}

func (b *cancellingBrowseBackend) Browse(ctx context.Context, _ BrowseOptions) (Session, error) {
	close(b.started)
	<-ctx.Done()
	return closeSignalSession{b.closed}, errors.New("cancelled startup")
}

type closeSignalSession struct{ closed chan struct{} }

func (s closeSignalSession) Refresh() error { return nil }
func (s closeSignalSession) Close() error   { close(s.closed); return nil }

func TestBrowserCloseCancelsStartupAndClosesPartialSession(t *testing.T) {
	backend := &cancellingBrowseBackend{started: make(chan struct{}), closed: make(chan struct{})}
	b := NewBrowser(BrowserOptions{Backend: backend})
	returned := make(chan error, 1)
	go func() { returned <- b.Start([]Interface{testInterface("en0")}) }()
	<-backend.started
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-backend.closed:
	default:
		t.Fatal("close returned before partial session was released")
	}
	if err := <-returned; err == nil {
		t.Fatal("cancelled start reported success")
	}
	if b.Err() != "" || len(b.Snapshot().Candidates) != 0 {
		t.Fatal("late error overwrote closed state")
	}
}

func TestBrowserCloseWaitsForExpiryAndDropsCache(t *testing.T) {
	backend := &captureBackend{hub: newHub()}
	b := NewBrowser(BrowserOptions{Backend: backend})
	for i := 0; i < 10; i++ {
		if err := b.Start([]Interface{testInterface("en0")}); err != nil {
			t.Fatal(err)
		}
		callback := backend.last()
		callback(recordsFor(testAnnouncement(1, "共享"), "en0"))
		if len(b.Snapshot().Candidates) != 1 {
			t.Fatal("test did not populate the cache")
		}
		b.mu.Lock()
		done := b.tickerDone
		b.mu.Unlock()
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		default:
			t.Fatal("close returned while expiry task was alive")
		}
		callback(recordsFor(testAnnouncement(1, "迟到公告"), "en0"))
		if len(b.Snapshot().Candidates) != 0 {
			t.Fatal("closed browser retained or revived candidates")
		}
	}
}

func TestBrowserShutdownPreventsLateStart(t *testing.T) {
	b := NewBrowser(BrowserOptions{Backend: newHubBackend(newHub())})
	if err := b.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if err := b.Start([]Interface{testInterface("en0")}); err == nil {
		t.Fatal("a late page-open revived the shutdown browser")
	}
	if err := b.Shutdown(); err != nil {
		t.Fatal(err)
	}
}
