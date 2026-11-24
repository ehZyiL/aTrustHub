package relay

import (
	"context"
	"testing"
	"time"
)

// The discovery preference is saved with the enable intent and never resurrects
// a share: the snapshot only exists while the share is committed and running.
func TestDiscoverySnapshotNeedsChoiceAndRunning(t *testing.T) {
	p, sink, _, c, _ := setupShare(t)
	if _, ok := c.DiscoverySnapshot(); ok {
		t.Fatal("关闭状态不应有公告")
	}

	// Enabled but never asked about discovery: still nothing.
	if err := c.Enable(context.Background(), EnableOptions{PointID: "p1", Discovery: false}); err != nil {
		t.Fatal(err)
	}
	view := c.View()
	if view.DiscoveryEnabled {
		t.Fatal("关闭发现时 View 不应报告已允许")
	}
	if _, ok := c.DiscoverySnapshot(); ok {
		t.Fatal("未允许发现时不应有公告")
	}
	if got := p.ShareSettings().DiscoveryEnabled; got == nil || *got {
		t.Fatalf("开启表单的选择没有落盘：%v", got)
	}

	// Now allow it on a running share: the snapshot describes the bound address.
	if err := c.SetDiscovery(true, "会议室"); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.DiscoverySnapshot(); ok && view.State != StateRunning {
		t.Fatal("非运行状态却有公告")
	}

	// A waiting share keeps the preference but publishes nothing.
	sink.setOffline(true)
	if err := c.Suspend(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Retry(context.Background()); err != nil {
		_ = err // Retry reports the wait as a state, not an error.
	}
	if got := c.View().State; got == StateRunning {
		t.Fatalf("前置条件：离线时不应回到 running")
	}
	if _, ok := c.DiscoverySnapshot(); ok {
		t.Fatal("等待状态下不应有公告")
	}
	settings := c.Settings()
	if settings.DiscoveryEnabled == nil || !*settings.DiscoveryEnabled {
		t.Fatal("等待状态不应丢掉发现偏好")
	}
	if settings.DiscoveryName != "会议室" {
		t.Fatalf("公开名称丢失：%q", settings.DiscoveryName)
	}
}

func TestSetDiscoveryRollsBackWhenTheSaveFails(t *testing.T) {
	p, _, _, c, _ := setupShare(t)
	if err := c.Enable(context.Background(), EnableOptions{PointID: "p1", Discovery: false}); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.failSave = true
	p.mu.Unlock()
	if err := c.SetDiscovery(true, "会议室"); err == nil {
		t.Fatal("保存失败时应当返回错误")
	}
	view := c.View()
	if view.DiscoveryEnabled {
		t.Fatal("保存失败后仍报告已允许")
	}
	if view.DiscoveryName != "" {
		t.Fatalf("保存失败后名称没有回滚：%q", view.DiscoveryName)
	}
	if _, ok := c.DiscoverySnapshot(); ok {
		t.Fatal("保存失败后仍可发布")
	}

	// The share itself is untouched by a failed preference write.
	if c.View().State != StateRunning {
		t.Fatalf("共享被偏好写入失败影响：%s", c.View().State)
	}
	if _, err := c.ShareCode(); err != nil {
		t.Fatalf("口令被偏好写入失败影响：%v", err)
	}
}

func TestDisableKeepsTheDiscoveryPreference(t *testing.T) {
	p, _, _, c, _ := setupShare(t)
	if err := c.Enable(context.Background(), EnableOptions{PointID: "p1", Discovery: true, DiscoveryName: "会议室"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved := p.ShareSettings()
	if saved.DiscoveryEnabled == nil || !*saved.DiscoveryEnabled {
		t.Fatal("关闭共享不应丢掉发现偏好")
	}
	if saved.DiscoveryName != "会议室" {
		t.Fatalf("关闭共享不应丢掉公开名称：%q", saved.DiscoveryName)
	}
	if saved.ShareID != "" || saved.Fingerprint != "" {
		t.Fatal("关闭共享应当撤销身份")
	}
	if _, ok := c.DiscoverySnapshot(); ok {
		t.Fatal("关闭共享后不应再有公告")
	}
}

func TestEnableRejectsAnInvalidDiscoveryName(t *testing.T) {
	_, _, _, c, _ := setupShare(t)
	err := c.Enable(context.Background(), EnableOptions{PointID: "p1", Discovery: true, DiscoveryName: "带\n换行"})
	if err == nil {
		t.Fatal("非法公开名称应当被拒绝")
	}
	if c.View().Enabled {
		t.Fatal("被拒绝的开启不应留下意图")
	}
}

func TestSetDiscoveryOnAClosedController(t *testing.T) {
	_, _, _, c, _ := setupShare(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDiscovery(true, ""); err == nil {
		t.Fatal("退出后不应还能改偏好")
	}
}

// Spec §8.2: a share that is Waiting (VPN not connected yet) publishes nothing,
// and starts publishing once the same instance reaches Running - without the UI
// being involved.
func TestWaitingSharePublishesWhenItBecomesRunning(t *testing.T) {
	p, sink, _, c, _ := setupShare(t)
	sink.setOffline(true)
	if err := c.Enable(context.Background(), EnableOptions{
		PointID: "p1", Discovery: true, DiscoveryName: "会议室",
	}); err != nil {
		t.Fatal(err)
	}
	if got := c.View().State; got != StateWaiting {
		t.Fatalf("离线时状态 = %s，want waiting", got)
	}
	if _, ok := c.DiscoverySnapshot(); ok {
		t.Fatal("等待状态不应有公告")
	}
	if got := p.ShareSettings().DiscoveryEnabled; got == nil || !*got {
		t.Fatal("等待状态不应丢掉发现偏好")
	}

	// The access point comes up; the same identity resumes.
	sink.setOffline(false)
	if err := c.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitState(t, c, StateRunning)
	ann, ok := c.DiscoverySnapshot()
	if !ok {
		t.Fatal("Running 后没有公告")
	}
	if ann.ShareID != c.Settings().ShareID || ann.Address == "" || ann.Port == 0 {
		t.Fatalf("公告内容不对：%+v", ann)
	}
	if ann.Name != "会议室" {
		t.Fatalf("公告名称不对：%q", ann.Name)
	}
}
