package model

import (
	"strings"
	"testing"
)

// A1/A5/A7: the discovery preference is three-state, survives a clone without
// sharing memory, and its name rules are enforced at every boundary.
func TestDiscoveryPreferenceIsThreeState(t *testing.T) {
	off := false
	on := true
	for _, tc := range []struct {
		name    string
		in      *bool
		wantPtr bool
		wantVal bool
	}{
		{"未选择", nil, false, false},
		{"明确关闭", &off, true, false},
		{"明确开启", &on, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := LANShareSettings{DiscoveryEnabled: tc.in}
			s.Normalize()
			if (s.DiscoveryEnabled != nil) != tc.wantPtr {
				t.Fatalf("指针状态被 Normalize 改掉：%v", s.DiscoveryEnabled)
			}
			if tc.wantPtr && *s.DiscoveryEnabled != tc.wantVal {
				t.Fatalf("值被改掉：%v", *s.DiscoveryEnabled)
			}
		})
	}
}

// The zero-value test must not be fooled by a discovery-only configuration: it
// decides whether Normalize backfills every other default.
func TestNormalizeStillBackfillsWithOnlyDiscoverySet(t *testing.T) {
	off := false
	var s Settings
	s.LANShare.DiscoveryEnabled = &off
	s.Normalize()
	if s.ListenHost == "" {
		t.Fatal("默认值没有补全：ListenHost 为空")
	}
	if s.AggregatePort == 0 {
		t.Fatal("默认值没有补全：AggregatePort 为 0")
	}
	if s.CaptureMode == "" {
		t.Fatal("默认值没有补全：CaptureMode 为空")
	}
	if s.LANShare.DiscoveryEnabled == nil || *s.LANShare.DiscoveryEnabled {
		t.Fatalf("Normalize 改动了用户的选择：%v", s.LANShare.DiscoveryEnabled)
	}
}

func TestCloneDoesNotShareTheDiscoveryPointer(t *testing.T) {
	on := true
	s := Settings{}
	s.LANShare.DiscoveryEnabled = &on
	clone := s.Clone()
	*clone.LANShare.DiscoveryEnabled = false
	if !*s.LANShare.DiscoveryEnabled {
		t.Fatal("修改副本影响了原配置")
	}
	// A nil pointer stays nil: "never asked" must survive a clone.
	empty := Settings{}
	if c := empty.Clone(); c.LANShare.DiscoveryEnabled != nil {
		t.Fatal("克隆把 nil 变成了指针")
	}
}

func TestDiscoveryNameRules(t *testing.T) {
	long := strings.Repeat("长", DiscoveryNameMaxRunes)
	for _, tc := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"正常", "会议室共享", true},
		{"emoji", "会议室 📺", true},
		{"边界 40 字", long, true},
		{"超 41 字", long + "长", false},
		{"空", "", false},
		{"控制字符", "坏\x00名字", false},
		{"换行", "两行\n名字", false},
		{"首尾空白", " 空白 ", false},
		{"制表符", "制表\t符", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidDiscoveryName(tc.in)
			if tc.ok && err != nil {
				t.Fatalf("应当接受：%v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("应当拒绝")
			}
		})
	}
}

func TestDefaultDiscoveryNameHidesIdentity(t *testing.T) {
	name := DefaultDiscoveryName("eBJ0VWay-sBH1H-FUhplQQ")
	if name != "Connect Hub 分享 eBJ0VW" {
		t.Fatalf("默认名称不对：%q", name)
	}
	for _, leak := range []string{"vpn.example.com", "公司", "u@Radius"} {
		if strings.Contains(name, leak) {
			t.Fatalf("默认名称泄漏了 %q", leak)
		}
	}
}
