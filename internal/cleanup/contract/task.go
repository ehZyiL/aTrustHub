// Package contract contains bounded desktop data, never system cleanup code.
package contract

import (
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/ehzyil/connect-hub/internal/components"
)

const (
	Capability     = "cleanup-task-v1"
	MaxFindings    = 500
	MaxBackups     = 100
	MaxLogs        = 128
	MaxText        = 1024
	MaxPlanBytes   = 32 << 20
	MaxStreamBytes = 8 << 20
	TaskTimeout    = 30 * time.Minute
	LeaseTimeout   = 15 * time.Second
)

const (
	Scan    = "scan"
	List    = "list-backups"
	Apply   = "apply"
	Restore = "restore"
)

type Request struct {
	components.Request
	ScanDir    string   `json:"scanDir,omitempty"`
	Selected   []string `json:"selected,omitempty"`
	BackupRoot string   `json:"backupRoot"`
	BackupID   string   `json:"backupId,omitempty"`
}

func (r Request) Check(now time.Time) error {
	if err := r.Request.Check(now); err != nil {
		return err
	}
	if r.Deadline.After(now.Add(TaskTimeout + time.Second)) {
		return errors.New("清理任务截止时间过长")
	}
	switch r.Operation {
	case Scan, List:
	case Apply:
		if r.ScanDir == "" || len(r.Selected) == 0 || len(r.Selected) > MaxFindings {
			return errors.New("请选择本次扫描的清理项")
		}
	case Restore:
		if !components.ValidID(r.BackupID) {
			return errors.New("备份标识无效")
		}
	default:
		return errors.New("未知清理操作")
	}
	for _, s := range append(append([]string{}, r.Selected...), r.ScanDir, r.BackupRoot) {
		if len(s) > 4096 || !utf8.ValidString(s) {
			return errors.New("清理参数超过上限")
		}
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(data) > components.MaxMessageBytes-components.MaxIDBytes {
		return errors.New("所选条目过多，清理请求超过消息上限")
	}
	return nil
}

type Finding struct {
	ID       string `json:"id"`
	Group    string `json:"group"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Deep     bool   `json:"deep"`
	Selected bool   `json:"selected"`
}

type Backup struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"createdAt"`
	Files        int       `json:"files"`
	Registry     int       `json:"registry"`
	Certificates int       `json:"certificates"`
	Policies     int       `json:"policies,omitempty"`
}

type Result struct {
	Outcome   string `json:"outcome"` // complete, canceled, failed
	Total     int    `json:"total,omitempty"`
	OK        int    `json:"ok,omitempty"`
	Failed    int    `json:"failed,omitempty"`
	Skipped   int    `json:"skipped,omitempty"`
	Reboot    int    `json:"reboot,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	BackupID  string `json:"backupId,omitempty"`
}

type Update struct {
	Finding   *Finding `json:"finding,omitempty"`
	Backup    *Backup  `json:"backup,omitempty"`
	Installed string   `json:"installed,omitempty"`
	Result    *Result  `json:"result,omitempty"`
}

// Text bounds display data without splitting a UTF-8 sequence.
func Text(s string) string {
	if len(s) <= MaxText {
		return s
	}
	s = s[:MaxText]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
