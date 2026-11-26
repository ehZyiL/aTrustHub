package service

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/cleanup/taskio"
	"github.com/ehzyil/connect-hub/internal/components"
)

// Recovery discovery is read-only and runs inside the list task. An interrupted
// mutation is never retried automatically and its directory is never deleted.
func reportInterruptedTasks(ctx context.Context, current string, emit Emit) error {
	d, err := os.Open(filepath.Dir(current))
	if err != nil {
		return err
	}
	defer d.Close()
	checked := 0
	for checked < 1000 {
		if err = ctx.Err(); err != nil {
			return err
		}
		entries, readErr := d.ReadDir(32)
		for _, entry := range entries {
			checked++
			if !entry.IsDir() || !strings.HasPrefix(entry.Name(), taskio.Prefix) {
				continue
			}
			dir := filepath.Join(filepath.Dir(current), entry.Name())
			if dir == current {
				continue
			}
			var req contract.Request
			if taskio.Read(dir, "request.json", &req) != nil || (req.Operation != contract.Apply && req.Operation != contract.Restore) {
				continue
			}
			cursor := components.Cursor{InstanceID: req.InstanceID, RequestID: req.RequestID}
			var tail taskio.Tail
			_ = tail.Read(filepath.Join(dir, "events.jsonl"), contract.MaxStreamBytes, func(e components.Event) error { cursor.Accept(e); return nil })
			if !cursor.Final {
				if err = emit("发现未确认完成的清理或恢复任务："+entry.Name()+"。请核对记录和备份后再决定恢复，程序不会自动重试。", contract.Update{}); err != nil {
					return err
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
	return emit("任务历史较多，仅核对最近读取的 1000 个目录；其余记录仍保留在数据目录。", contract.Update{})
}
