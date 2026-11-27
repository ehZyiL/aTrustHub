//go:build linux

package desktop

import (
	"os"
	"strconv"
	"strings"
)

// residentBytes 返回当前常驻内存，用于把「修剪工作集」的效果写进日志。
// /proc/self/statm 的第二列是常驻页数；读不到就返回 0，调用方退回不带数字的日志。
func residentBytes() int64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || pages <= 0 {
		return 0
	}
	return pages * int64(os.Getpagesize())
}
