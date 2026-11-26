package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
)

type ApplyOptions struct {
	Plan          *Plan
	Context       context.Context
	ReportPath    string
	OnlyIDs       []string
	SkipIDs       []string
	BackupRootDir string
	OnEvent       func(ReportEvent) error
}

// A durable intent precedes each indivisible operation. Cancellation between
// items leaves the previous item complete and the next untouched. A crash with
// an unmatched intent is indeterminate, never reported as success.
func checkpoint(ctx context.Context, rw *ReportWriter, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := rw.Err(); err != nil {
		return err
	}
	if rw != nil && id != "" {
		return rw.WriteEvent(ReportEvent{Event: "intent", ID: id})
	}
	return nil
}

func readManifest(path string, out *BackupManifest) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil {
		return err
	}
	if !i.Mode().IsRegular() || i.Size() > contract.MaxPlanBytes {
		return errors.New("备份清单无效或超过上限")
	}
	dec := json.NewDecoder(f)
	if err = dec.Decode(out); err != nil {
		return err
	}
	if out.Version != 1 {
		return errors.New("不支持的备份版本")
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return errors.New("备份清单包含尾随数据")
	}
	return nil
}

func validateRestore(dir string, m *BackupManifest) error {
	check := func(rel string) (string, error) {
		if !filepath.IsLocal(rel) {
			return "", errors.New("备份文件必须位于备份目录内")
		}
		path := filepath.Join(dir, rel)
		for p := path; p != filepath.Clean(dir); p = filepath.Dir(p) {
			i, err := os.Lstat(p)
			if err != nil {
				return "", err
			}
			if i.Mode()&os.ModeSymlink != 0 {
				return "", errors.New("备份文件不能是链接")
			}
		}
		return path, nil
	}
	for _, r := range m.Registry {
		if _, err := check(r.BackupFile); err != nil {
			return err
		}
	}
	for _, c := range m.Certificates {
		if _, err := check(c.BackupFile); err != nil {
			return err
		}
	}
	for _, f := range m.Files {
		path, err := check(f.BackupPath)
		if err != nil {
			return err
		}
		if !filepath.IsAbs(f.OriginalPath) {
			return errors.New("恢复目标不是绝对路径")
		}
		if f.SHA256 != "" {
			in, err := os.Open(path)
			if err != nil {
				return err
			}
			h := sha256.New()
			_, err = io.Copy(h, in)
			in.Close()
			if err != nil {
				return err
			}
			if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), f.SHA256) {
				return fmt.Errorf("备份校验失败: %s", f.BackupPath)
			}
		}
	}
	return nil
}
