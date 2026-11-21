package wincapture

import (
	"context"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Serialize adapter allocation across desktops/users. Without this lock two
// helpers could both inspect the same free alias subnet before either adds
// its route. The lease itself is not locked: each owns its specific resources.
func networkTransaction(ctx context.Context) (func(), error) {
	return namedNetworkLock(ctx, `Global\ConnectHub-NetworkTransaction`)
}

func runtimeOwnership(ctx context.Context) (func(), error) {
	return namedNetworkLock(ctx, `Global\ConnectHub-NetworkOwner`)
}

func namedNetworkLock(ctx context.Context, lockName string) (func(), error) {
	// Win32 mutex ownership belongs to an OS thread, not a goroutine.
	runtime.LockOSThread()
	locked := false
	defer func() {
		if !locked {
			runtime.UnlockOSThread()
		}
	}()
	name, _ := windows.UTF16PtrFromString(lockName)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if err != nil {
		return nil, windowsError("创建网络事务安全描述符", err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateMutex(&sa, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, windowsError("创建网络事务锁 CreateMutex", err)
	}
	for {
		if err := ctx.Err(); err != nil {
			windows.CloseHandle(h)
			return nil, err
		}
		state, err := windows.WaitForSingleObject(h, 50)
		if err != nil {
			windows.CloseHandle(h)
			return nil, windowsError("等待网络事务锁 WaitForSingleObject", err)
		}
		if state == windows.WAIT_OBJECT_0 || state == windows.WAIT_ABANDONED {
			locked = true
			return func() { windows.ReleaseMutex(h); windows.CloseHandle(h); runtime.UnlockOSThread() }, nil
		}
	}
}
