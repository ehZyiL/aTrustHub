package desktop

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/egoist/mygo/ui"
	relayclient "github.com/ehzyil/connect-hub/internal/relay/client"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
)

type pairManageTestControl struct {
	relayclient.Controller
	control func(context.Context, relay.PairCommand) (relay.PairView, error)
}

func (p *pairManageTestControl) PairControl(ctx context.Context, cmd relay.PairCommand) (relay.PairView, error) {
	return p.control(ctx, cmd)
}

func (p *pairManageTestControl) Settings() relay.Settings { return relay.Settings{} }

func (p *pairManageTestControl) PauseSharing(ctx context.Context) error {
	_, err := p.control(ctx, relay.PairCommand{Operation: "pause"})
	return err
}

func (p *pairManageTestControl) ResumeSharing(ctx context.Context) error {
	_, err := p.control(ctx, relay.PairCommand{Operation: "resume"})
	return err
}

func pairManageSynctest(t *testing.T, test func(*testing.T)) {
	t.Helper()
	// MyGo's shared raster workers outlive a test and cannot join a synctest
	// bubble. Render on one core so this bubble only owns its own goroutines.
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	synctest.Test(t, test)
}

// The real view and result drain run on the test's UI thread. Both framework
// After frames and application invalidations feed that same view; synctest
// advances the application's timers without wall-clock sleeps.
func pairManageTester(t *testing.T, control *pairManageTestControl) (*app, *ui.Tester, func(time.Duration)) {
	t.Helper()
	return pairManageTesterWithView(t, control, relay.View{Enabled: true, State: relay.StateRunning, Pairing: true})
}

func pairManageTesterWithView(t *testing.T, control *pairManageTestControl, view relay.View) (*app, *ui.Tester, func(time.Duration)) {
	t.Helper()
	a := &app{lanShare: control, lanShareUI: lanShareDraft{
		open: true, results: make(chan lanShareResult, 4),
		pair: relay.PairView{Invitation: &relay.Invitation{
			ID: "current", Capacity: 5, ExpiresAt: time.Now().Add(time.Minute),
		}, Requests: []relay.PairRequest{{ID: "request", State: "pending", Name: "requester"}},
			Devices: []relay.PairedDevice{{ID: "device", Name: "saved device"}}},
	}}
	frames := make(chan struct{}, 32)
	a.painter().draw = func() {
		select {
		case frames <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() { a.windowHidden.Store(true) })
	t.Cleanup(a.stopPairManage)
	t.Cleanup(a.stopLANSharePause)
	tester := ui.NewTester(func(c *ui.Context) {
		if a.lanShareUI.open {
			a.drainLANShareResults()
			a.pairingManageView(c, view)
		} else {
			a.lanShareView(c)
		}
	}, 900, 900)
	flush := func() {
		for range 20 {
			synctest.Wait()
			select {
			case <-frames:
				tester.Frame()
			default:
				return
			}
		}
		t.Fatal("pairing management did not settle")
	}
	flush()
	return a, tester, func(d time.Duration) {
		time.Sleep(d)
		tester.Advance(d)
		flush()
	}
}

func TestPairManagePollingContinuesAfterInvitationAction(t *testing.T) {
	for _, operation := range []string{"create", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			pairManageSynctest(t, func(t *testing.T) {
				lists, actions := 0, 0
				control := &pairManageTestControl{control: func(_ context.Context, cmd relay.PairCommand) (relay.PairView, error) {
					if cmd.Operation == "list" {
						lists++
					} else {
						actions++
					}
					return relay.PairView{Invitation: &relay.Invitation{ID: "current", Capacity: 5, ExpiresAt: time.Now().Add(time.Minute)}}, nil
				}}
				_, tester, advance := pairManageTester(t, control)
				advance(500 * time.Millisecond)
				button := "生成邀请码"
				if operation == "cancel" {
					button = "取消邀请码"
				}
				if err := tester.Click(button); err != nil {
					t.Fatal(err)
				}
				advance(0)
				if actions != 1 {
					t.Fatalf("invitation action count = %d, want 1", actions)
				}
				before := lists
				// The old scheduled frame lands less than a second after the
				// action. It must still leave a future refresh scheduled.
				advance(600 * time.Millisecond)
				advance(time.Second)
				if lists <= before {
					t.Fatalf("polling stopped after %s: list calls = %d", operation, lists)
				}
			})
		})
	}
}

func TestPairManageBackgroundRefreshAllowsActions(t *testing.T) {
	for _, tt := range []struct {
		operation string
		button    string
		id        string
	}{
		{"create", "生成邀请码", ""},
		{"cancel", "取消邀请码", ""},
		{"approve", "批准 request", "request"},
		{"reject", "拒绝 request", "request"},
		{"revoke", "撤销 device", "device"},
		{"revoke-all", "确认撤销全部设备", ""},
		{"pause", "暂停共享", ""},
	} {
		t.Run(tt.operation, func(t *testing.T) {
			pairManageSynctest(t, func(t *testing.T) {
				var actions []relay.PairCommand
				release := make(chan struct{})
				t.Cleanup(func() { close(release); synctest.Wait() })
				control := &pairManageTestControl{control: func(ctx context.Context, cmd relay.PairCommand) (relay.PairView, error) {
					if cmd.Operation == "list" {
						select {
						case <-ctx.Done():
						case <-release:
						}
						return relay.PairView{}, ctx.Err()
					}
					actions = append(actions, cmd)
					return relay.PairView{}, nil
				}}
				_, tester, advance := pairManageTester(t, control)
				if tt.operation == "revoke-all" {
					if err := tester.Click("撤销全部已配对设备…"); err != nil {
						t.Fatal(err)
					}
				}
				if err := tester.Click(tt.button); err != nil {
					t.Fatal(err)
				}
				advance(0)
				if len(actions) != 1 || actions[0].Operation != tt.operation || actions[0].ID != tt.id {
					t.Fatalf("background refresh blocked or changed %s: actions = %+v", tt.operation, actions)
				}
			})
		})
	}
}

func TestPairManageSlowRefreshDoesNotOverlapAndRecovers(t *testing.T) {
	pairManageSynctest(t, func(t *testing.T) {
		lists := 0
		release := make(chan struct{})
		control := &pairManageTestControl{control: func(ctx context.Context, cmd relay.PairCommand) (relay.PairView, error) {
			lists++
			if lists == 1 {
				select {
				case <-release:
				case <-ctx.Done():
					return relay.PairView{}, ctx.Err()
				}
			}
			return relay.PairView{}, nil
		}}
		a, _, advance := pairManageTester(t, control)
		advance(3 * time.Second)
		if lists != 1 || a.lanShareUI.pairBusy {
			t.Fatalf("slow refresh overlapped or disabled actions: calls=%d busy=%v", lists, a.lanShareUI.pairBusy)
		}
		close(release)
		advance(0)
		before := lists
		advance(time.Second)
		if lists <= before {
			t.Fatal("polling stopped after a slow refresh completed")
		}
	})
}

func TestPairManageLateRefreshCannotReplaceAction(t *testing.T) {
	for _, operation := range []string{"create", "cancel"} {
		for _, lateError := range []bool{false, true} {
			name := operation + "/success"
			if lateError {
				name = operation + "/error"
			}
			t.Run(name, func(t *testing.T) {
				pairManageSynctest(t, func(t *testing.T) {
					release := make(chan struct{})
					finish := sync.OnceFunc(func() { close(release) })
					var refreshCtx context.Context
					control := &pairManageTestControl{control: func(ctx context.Context, cmd relay.PairCommand) (relay.PairView, error) {
						if cmd.Operation == "list" {
							refreshCtx = ctx
							<-release // Model a response already in flight at cancellation.
							if lateError {
								return relay.PairView{}, errors.New("stale refresh error")
							}
							return relay.PairView{Invitation: &relay.Invitation{ID: "stale"}}, nil
						}
						return relay.PairView{PIN: "12345678", Invitation: &relay.Invitation{
							ID: "new", Capacity: 5, ExpiresAt: time.Now().Add(time.Minute), Cancelled: operation == "cancel",
						}}, nil
					}}
					a, tester, advance := pairManageTester(t, control)
					t.Cleanup(func() { finish(); synctest.Wait() })
					button := "生成邀请码"
					if operation == "cancel" {
						button = "取消邀请码"
					}
					if err := tester.Click(button); err != nil {
						t.Fatal(err)
					}
					advance(0)
					if refreshCtx.Err() == nil {
						t.Fatal("explicit action did not cancel the passive refresh")
					}
					// Deliver the old result after the action has updated the UI.
					finish()
					advance(0)
					wantPIN := "12345678"
					if operation == "cancel" {
						wantPIN = ""
					}
					if a.lanShareUI.pair.Invitation == nil || a.lanShareUI.pair.Invitation.ID != "new" || a.lanShareUI.pairPIN != wantPIN || a.lanShareUI.err != "" {
						t.Fatal("late refresh changed the current invitation, PIN, or error")
					}
				})
			})
		}
	}
}

func TestPairManageCloseReopenDiscardsLateResult(t *testing.T) {
	pairManageSynctest(t, func(t *testing.T) {
		lists := 0
		release := make(chan struct{})
		finish := sync.OnceFunc(func() { close(release) })
		var actionCtx context.Context
		control := &pairManageTestControl{control: func(ctx context.Context, cmd relay.PairCommand) (relay.PairView, error) {
			if cmd.Operation == "create" {
				actionCtx = ctx
				<-release
				return relay.PairView{PIN: "12345678", Invitation: &relay.Invitation{ID: "closed"}}, nil
			}
			lists++
			return relay.PairView{Invitation: &relay.Invitation{ID: "current"}}, nil
		}}
		a, tester, advance := pairManageTester(t, control)
		t.Cleanup(func() { finish(); synctest.Wait() })
		if err := tester.Click("生成邀请码"); err != nil {
			t.Fatal(err)
		}
		advance(0)
		a.lanShareUI.open = false
		tester.Frame()
		if actionCtx.Err() == nil || a.lanShareUI.pairBusy || a.lanShareUI.pairResults != nil {
			t.Fatal("closing the panel did not detach and cancel its request")
		}
		before := lists
		advance(2 * time.Second)
		if lists != before {
			t.Fatal("closed panel continued polling")
		}
		a.openLANShare()
		advance(0)
		finish()
		advance(0)
		if a.lanShareUI.pairPIN != "" || a.lanShareUI.pair.Invitation.ID != "current" || a.lanShareUI.err != "" || lists <= before {
			t.Fatal("reopened panel accepted a previous panel's result or stopped refreshing")
		}
	})
}

func TestPairManageExplicitActionSerializesControls(t *testing.T) {
	pairManageSynctest(t, func(t *testing.T) {
		var actions []string
		control := &pairManageTestControl{control: func(ctx context.Context, cmd relay.PairCommand) (relay.PairView, error) {
			if cmd.Operation == "list" {
				return relay.PairView{Invitation: &relay.Invitation{ID: "current", Capacity: 5, ExpiresAt: time.Now().Add(time.Minute)}}, nil
			}
			actions = append(actions, cmd.Operation)
			<-ctx.Done()
			return relay.PairView{}, ctx.Err()
		}}
		a, tester, advance := pairManageTester(t, control)
		if err := tester.Click("生成邀请码"); err != nil {
			t.Fatal(err)
		}
		advance(0)
		for _, button := range []string{"生成邀请码", "取消邀请码", "暂停共享"} {
			if err := tester.Click(button); err != nil {
				t.Fatal(err)
			}
		}
		advance(2 * time.Second)
		if len(actions) != 1 || actions[0] != "create" || !a.lanShareUI.pairBusy {
			t.Fatalf("explicit actions overlapped: actions=%v busy=%v", actions, a.lanShareUI.pairBusy)
		}
	})
}

func TestPairManageHiddenPanelStopsPollingAndRestores(t *testing.T) {
	for _, hidden := range []string{"tray", "minimized"} {
		t.Run(hidden, func(t *testing.T) {
			pairManageSynctest(t, func(t *testing.T) {
				lists := 0
				control := &pairManageTestControl{control: func(context.Context, relay.PairCommand) (relay.PairView, error) {
					lists++
					return relay.PairView{}, nil
				}}
				a, tester, advance := pairManageTester(t, control)
				if hidden == "tray" {
					a.windowHidden.Store(true)
				} else {
					a.minimized.Store(true)
				}
				tester.Frame()
				before := lists
				advance(3 * time.Second)
				if lists != before {
					t.Fatal("hidden panel continued polling")
				}
				a.windowHidden.Store(false)
				a.minimized.Store(false)
				tester.Frame()
				advance(0)
				if lists <= before {
					t.Fatal("restored panel did not refresh")
				}
			})
		})
	}
}

func TestPairManageFailedCancelKeepsInvitation(t *testing.T) {
	pairManageSynctest(t, func(t *testing.T) {
		control := &pairManageTestControl{control: func(_ context.Context, cmd relay.PairCommand) (relay.PairView, error) {
			if cmd.Operation == "cancel" {
				return relay.PairView{}, errors.New("cancel failed")
			}
			return relay.PairView{Invitation: &relay.Invitation{ID: "current", Capacity: 5, ExpiresAt: time.Now().Add(time.Minute)}}, nil
		}}
		a, tester, advance := pairManageTester(t, control)
		a.lanShareUI.pairPIN = "12345678"
		if err := tester.Click("取消邀请码"); err != nil {
			t.Fatal(err)
		}
		advance(0)
		if a.lanShareUI.pairPIN != "12345678" || a.lanShareUI.pair.Invitation == nil || a.lanShareUI.pair.Invitation.Cancelled || a.lanShareUI.err != "cancel failed" {
			t.Fatal("failed cancellation hid the active invitation or its error")
		}
	})
}

func TestPairManagePauseKeepsDevicesAndClearsEphemeralState(t *testing.T) {
	a := &app{lanShareUI: lanShareDraft{
		pairAt: time.Now(), pairPIN: "12345678",
		pair: relay.PairView{
			Invitation: &relay.Invitation{ID: "old"},
			Requests:   []relay.PairRequest{{ID: "pending", State: "pending"}},
			Devices:    []relay.PairedDevice{{ID: "saved", Name: "saved device"}},
		},
	}}
	tester := ui.NewTester(func(c *ui.Context) {
		a.pairingManageView(c, relay.View{Enabled: true, Paused: true, Pairing: true})
	}, 900, 900)
	if a.lanShareUI.pairPIN != "" || a.lanShareUI.pair.Invitation != nil || len(a.lanShareUI.pair.Requests) != 0 || len(a.lanShareUI.pair.Devices) != 1 {
		t.Fatal("paused panel retained an invitation/request or discarded authorized devices")
	}
	if !tester.HasText("恢复共享") || !tester.HasText("当前邀请码和临时配对请求会失效") || !tester.HasText("saved device") {
		t.Fatal("paused panel did not explain its lifecycle or show saved devices")
	}
}
