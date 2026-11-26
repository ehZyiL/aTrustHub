package service

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/cleanup/taskio"
)

// RiskLevel 风险等级枚举
type RiskLevel string

const (
	RiskNormal RiskLevel = "normal"
	RiskDeep   RiskLevel = "deep"
)

// ActionType 清理动作枚举
type ActionType string

const (
	ActionDeleteService        ActionType = "delete-service"
	ActionKillProcess          ActionType = "kill-process"
	ActionDeleteRegistry       ActionType = "delete-registry"
	ActionDeletePath           ActionType = "delete-path"
	ActionClearDosDevice       ActionType = "clear-dos-device"
	ActionDeletePolicyValue    ActionType = "delete-policy-value"
	ActionDeleteDriverPackage  ActionType = "delete-driver-package"
	ActionUninstallWinsockProv ActionType = "uninstall-winsock-provider"
	ActionRemoveDevice         ActionType = "remove-device"
	ActionDeleteCert           ActionType = "delete-cert"
)

// InstalledApp 已安装的官方客户端信息（仅作独立引导用）
type InstalledApp struct {
	Name            string `json:"name"`
	UninstallString string `json:"uninstall"`
	Hive            string `json:"hive"`
	Key             string `json:"key"`
}

// Finding 扫描出的单项残留
type Finding struct {
	ID       string                 `json:"id"`
	Group    string                 `json:"group"`
	Family   string                 `json:"family,omitempty"` // "ec" | "atrust"
	Title    string                 `json:"title"`
	Detail   string                 `json:"detail"`
	Risk     RiskLevel              `json:"risk"`
	Action   ActionType             `json:"action"`
	Params   map[string]interface{} `json:"params"`
	Selected bool                   `json:"selected"`
}

// Plan 扫描产出的待办清单
type Plan struct {
	Version                          int            `json:"version"`
	ScannedAt                        time.Time      `json:"scannedAt"`
	Elevated                         bool           `json:"elevated"`
	RequiresElevationForCompleteScan bool           `json:"requiresElevationForCompleteScan"`
	Installed                        []InstalledApp `json:"installed"`
	Findings                         []Finding      `json:"findings"`
	Warnings                         []string       `json:"warnings,omitempty"`
}

// ReportStatus 单项执行状态枚举
type ReportStatus string

const (
	StatusOk       ReportStatus = "ok"
	StatusReboot   ReportStatus = "reboot"
	StatusFailed   ReportStatus = "failed"
	StatusSkipped  ReportStatus = "skipped"
	StatusCanceled ReportStatus = "canceled"
)

// ReportEvent report.jsonl 流事件
type ReportEvent struct {
	TS             time.Time    `json:"ts"`
	Event          string       `json:"event"` // "start" | "backup" | "item" | "end"
	ID             string       `json:"id,omitempty"`
	Status         ReportStatus `json:"status,omitempty"`
	Message        string       `json:"message,omitempty"`
	Total          int          `json:"total,omitempty"`
	Elevated       bool         `json:"elevated,omitempty"`
	BackupID       string       `json:"backupId,omitempty"`
	BackupManifest string       `json:"backupManifest,omitempty"`
	Ok             int          `json:"ok,omitempty"`
	Failed         int          `json:"failed,omitempty"`
	Reboot         int          `json:"reboot,omitempty"`
	Exit           int          `json:"exit,omitempty"`
}

// RegistryBackupItem 注册表备份元数据
type RegistryBackupItem struct {
	Hive       string `json:"hive"`
	Key        string `json:"key"`
	View       string `json:"view,omitempty"`
	BackupFile string `json:"backupFile"`
}

// FileBackupItem 文件备份元数据
type FileBackupItem struct {
	OriginalPath string `json:"originalPath"`
	BackupPath   string `json:"backupPath"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256,omitempty"`
}

// CertBackupItem 证书备份元数据
type CertBackupItem struct {
	Store      string `json:"store"`
	Thumbprint string `json:"thumbprint"`
	Subject    string `json:"subject"`
	BackupFile string `json:"backupFile"`
	// Nil preserves legacy manifests, which restored into LocalMachine.
	LocalMachine *bool `json:"localMachine,omitempty"`
}

// PolicyBackupItem 策略备份元数据
type PolicyBackupItem struct {
	Hive  string `json:"hive"`
	View  string `json:"view,omitempty"`
	Key   string `json:"key"`
	Value string `json:"value"`
	Data  string `json:"data,omitempty"`
}

// WinsockBackupItem Winsock 状态备份
type WinsockBackupItem struct {
	SnapshotBeforeReset string `json:"snapshotBeforeReset,omitempty"`
}

// BackupManifest backup-manifest.json 结构
type BackupManifest struct {
	Version      int                  `json:"version"`
	BackupID     string               `json:"backupId"`
	CreatedAt    time.Time            `json:"createdAt"`
	PlanSnapshot string               `json:"planSnapshot"`
	Registry     []RegistryBackupItem `json:"registry"`
	Files        []FileBackupItem     `json:"files"`
	Certificates []CertBackupItem     `json:"certificates"`
	Policies     []PolicyBackupItem   `json:"policies"`
	Winsock      WinsockBackupItem    `json:"winsock"`
}

// ReportWriter 线程安全的 report.jsonl 追加写入器
type ReportWriter struct {
	mu      sync.Mutex
	file    *os.File
	enc     *json.Encoder
	onEvent func(ReportEvent) error
	err     error
}

// NewReportWriter 创建并初始化报告写入器
func NewReportWriter(path string) (*ReportWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &ReportWriter{
		file: f,
		enc:  json.NewEncoder(f),
	}, nil
}

// WriteEvent 写入单条事件并立即持久化刷盘
func (rw *ReportWriter) WriteEvent(ev ReportEvent) error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if ev.TS.IsZero() {
		ev.TS = time.Now()
	}

	if rw.err != nil {
		return rw.err
	}
	if err := rw.enc.Encode(ev); err != nil {
		rw.err = err
		return err
	}
	if err := rw.file.Sync(); err != nil {
		rw.err = err
		return err
	}
	if rw.onEvent != nil {
		rw.err = rw.onEvent(ev)
	}
	return rw.err
}

func (rw *ReportWriter) Err() error {
	if rw == nil {
		return nil
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.err
}

// Close 关闭文件句柄
func (rw *ReportWriter) Close() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.file.Close()
}

// ReadPlanFromReader 从 io.Reader 读取 Plan
func ReadPlanFromReader(r io.Reader) (*Plan, error) {
	data, err := io.ReadAll(io.LimitReader(r, contract.MaxPlanBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > contract.MaxPlanBytes {
		return nil, errors.New("清理计划超过上限")
	}
	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Version != 2 {
		return nil, errors.New("不支持的清理计划版本")
	}
	return &p, nil
}

// SavePlanToFile 保存 Plan 到目标路径
func SavePlanToFile(path string, plan *Plan) error {
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > contract.MaxPlanBytes {
		return errors.New("清理计划超过上限")
	}
	return taskio.WriteBytes(filepath.Dir(path), filepath.Base(path), data)
}
