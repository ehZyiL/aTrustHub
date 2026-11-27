//go:build linux || windows || darwin

package desktop

import (
	"strings"
	"testing"
)

// Linux 读取 /proc/self/statm，Windows 调用 GetProcessMemoryInfo；读得到，常驻内存才算得出来。
func TestResidentBytesReturnsPositive(t *testing.T) {
	if got := residentBytes(); got <= 0 {
		t.Fatalf("residentBytes() = %d，应当读到本进程的常驻内存", got)
	}
}

// 修剪时把内存变化写进日志，用户才能在访问日志里看到「省了多少」。
func TestTrimMemoryLogsResidentChange(t *testing.T) {
	a := testApp(t)
	a.trimMemory()
	logged := tailLog(a.bus.Tail(5))
	if !strings.Contains(logged, "已修剪工作集") {
		t.Fatalf("修剪没有写日志：%q", logged)
	}
	if !strings.Contains(logged, "常驻") || !strings.Contains(logged, "MB →") {
		t.Errorf("日志里应当带上修剪前后的常驻内存：%q", logged)
	}
}
