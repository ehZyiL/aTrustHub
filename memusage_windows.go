//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

// residentBytes 在 Windows 上调用 GetProcessMemoryInfo 读取当前进程的物理工作集（WorkingSetSize）。
func residentBytes() int64 {
	psapi := syscall.NewLazyDLL("psapi.dll")
	getProcessMemoryInfo := psapi.NewProc("GetProcessMemoryInfo")
	handle, err := syscall.GetCurrentProcess()
	if err != nil || handle == 0 {
		return 0
	}
	var pmc processMemoryCounters
	pmc.cb = uint32(unsafe.Sizeof(pmc))
	r1, _, _ := getProcessMemoryInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.cb))
	if r1 == 0 {
		return 0
	}
	return int64(pmc.workingSetSize)
}
