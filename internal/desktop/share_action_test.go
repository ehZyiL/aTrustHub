package desktop

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

func TestShareRegressionDiscoveryReplyKeepsPauseBusy(t *testing.T) {
	pairManageSynctest(t, func(t *testing.T) {
		release := make(chan struct{})
		finish := sync.OnceFunc(func() { close(release) })
		defer finish()
		pauses := 0
		control := &pairManageTestControl{control: func(ctx context.Context, cmd contract.PairCommand) (contract.PairView, error) {
			if cmd.Operation == "pause" {
				pauses++
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
			return contract.PairView{}, nil
		}}
		a, tester, advance := pairManageTester(t, control)
		if err := tester.Click("暂停共享"); err != nil {
			t.Fatal(err)
		}
		advance(0)
		if pauses != 1 || !a.lanShareUI.busy {
			t.Fatal("pause did not start")
		}
		// This is the result emitted by toggleLANDiscovery. The controller's
		// preference operation can finish while PauseSharing waits in Close.
		a.lanShareResultPoster()(lanShareResult{action: "discovery", notice: "preference saved"})
		advance(0)
		if !a.lanShareUI.busy {
			t.Error("discovery result cleared busy while pause was still pending")
		}
		if err := tester.Click("暂停共享"); err != nil {
			t.Fatal(err)
		}
		advance(0)
		if pauses != 1 {
			t.Errorf("unrelated reply allowed overlapping pause actions: count=%d", pauses)
		}
		finish()
		advance(0)
	})
}

func TestShareRegressionOldPauseReplyDoesNotFinishNewPanelAction(t *testing.T) {
	pairManageSynctest(t, func(t *testing.T) {
		releases := []chan struct{}{make(chan struct{}), make(chan struct{})}
		finishFirst := sync.OnceFunc(func() { close(releases[0]) })
		finishSecond := sync.OnceFunc(func() { close(releases[1]) })
		defer finishFirst()
		defer finishSecond()
		pauses := 0
		control := &pairManageTestControl{control: func(ctx context.Context, cmd contract.PairCommand) (contract.PairView, error) {
			if cmd.Operation == "pause" {
				index := pauses
				pauses++
				// Model an already dispatched backend operation whose reply can
				// still arrive after the panel cancels its request.
				<-releases[index]
				if index == 0 {
					return contract.PairView{}, errors.New("old panel pause failed")
				}
			}
			return contract.PairView{}, nil
		}}
		a, tester, advance := pairManageTester(t, control)
		if err := tester.Click("暂停共享"); err != nil {
			t.Fatal(err)
		}
		advance(0)
		a.lanShareUI.open = false
		tester.Frame()
		a.openLANShare()
		tester.Frame()
		advance(0)
		if err := tester.Click("暂停共享"); err != nil {
			t.Fatal(err)
		}
		advance(0)
		if pauses != 2 || !a.lanShareUI.busy {
			t.Fatal("new panel action did not start")
		}
		finishFirst()
		advance(0)
		if !a.lanShareUI.busy || a.lanShareUI.err != "" {
			t.Errorf("old pause result affected new panel: busy=%v err=%q", a.lanShareUI.busy, a.lanShareUI.err)
		}
		finishSecond()
		advance(time.Millisecond)
	})
}

func TestResumeReplyIsScopedToPanelAndBusyOwner(t *testing.T) {
	pairManageSynctest(t, func(t *testing.T) {
		release := make(chan struct{})
		finish := sync.OnceFunc(func() { close(release) })
		defer finish()
		var resumeCtx context.Context
		control := &pairManageTestControl{control: func(ctx context.Context, cmd contract.PairCommand) (contract.PairView, error) {
			if cmd.Operation == "resume" {
				resumeCtx = ctx
				<-release
				return contract.PairView{}, errors.New("old resume reply")
			}
			return contract.PairView{}, nil
		}}
		a, tester, advance := pairManageTesterWithView(t, control, contract.View{Enabled: true, Paused: true, State: contract.StateWaiting, Pairing: true})
		if err := tester.Click("恢复共享"); err != nil {
			t.Fatal(err)
		}
		advance(0)
		if resumeCtx == nil || !a.lanShareUI.busy {
			t.Fatal("resume did not start")
		}
		a.lanShareResultPoster()(lanShareResult{action: "discovery-name"})
		advance(0)
		if !a.lanShareUI.busy {
			t.Fatal("discovery rename finished the pending resume")
		}
		a.lanShareUI.open = false
		tester.Frame()
		if !errors.Is(resumeCtx.Err(), context.Canceled) {
			t.Fatal("closed panel retained resume request")
		}
		a.openLANShare()
		a.lanShareUI.busy, a.lanShareUI.busyAction = true, "retry"
		finish()
		advance(0)
		if !a.lanShareUI.busy || a.lanShareUI.err != "" {
			t.Fatalf("old resume reply changed new panel: busy=%v err=%q", a.lanShareUI.busy, a.lanShareUI.err)
		}
	})
}

func TestOldPanelDisableAndDiscoveryRepliesAreDetached(t *testing.T) {
	a := &app{}
	a.openLANShare()
	oldPost := a.lanShareResultPoster()
	a.openLANShare()
	d := &a.lanShareUI
	d.busy, d.busyAction, d.discoveryBusy = true, "enable", true
	oldPost(lanShareResult{action: "disable"})
	oldPost(lanShareResult{action: "discovery", err: errors.New("old discovery reply"), saveFailed: true})
	a.drainLANShareResults()
	if !d.open || !d.busy || !d.discoveryBusy || d.err != "局域网分享尚未初始化" || d.discoverySavePending {
		t.Fatalf("old panel replies changed the new panel: %+v", d)
	}
}
