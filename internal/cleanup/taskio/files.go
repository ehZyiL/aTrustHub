// Package taskio implements the cleanup component's private task mailbox.
// Complete plans and recovery journals stay on disk, outside GUI snapshots.
package taskio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ehzyil/connect-hub/internal/components"
)

const Prefix = "connect-hub-cleanup-"

func NewDir(root string) (string, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	id, err := components.NewID()
	if err != nil {
		return "", err
	}
	dir, err := filepath.Abs(filepath.Join(root, Prefix+id))
	if err != nil {
		return "", err
	}
	if err := privateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func ValidateDir(dir string) error {
	if !filepath.IsAbs(dir) || !strings.HasPrefix(filepath.Base(dir), Prefix) {
		return errors.New("无效清理任务目录")
	}
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("任务路径不能包含链接")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

// Write publishes a complete document once. A reader never observes a partial
// request, cancellation or hello. Repeated writes require a different name.
func Write(dir, name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > components.MaxMessageBytes {
		return errors.New("任务消息过大")
	}
	return WriteBytes(dir, name, data)
}

func WriteBytes(dir, name string, data []byte) error {
	if filepath.Base(name) != name {
		return errors.New("无效任务文件名")
	}
	tmp, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return retrySharing(func() error { return os.Rename(tmp.Name(), filepath.Join(dir, name)) })
}

func Read(dir, name string, out any) error {
	f, err := openMailbox(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("任务文件不是普通文件")
	}
	return components.Decode(f, out)
}

// Tail retains only one partial line and the current offset. It never rereads
// an entire report and rejects truncation or an oversized message.
type Tail struct {
	Offset  int64
	pending []byte
}

func (t *Tail) Read(path string, maxBytes int64, consume func(components.Event) error) error {
	f, err := openMailbox(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < t.Offset || info.Size() > maxBytes {
		return errors.New("任务报告截断或超过大小上限")
	}
	if _, err = f.Seek(t.Offset, io.SeekStart); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	for {
		n, readErr := f.Read(buf)
		t.Offset += int64(n)
		for _, b := range buf[:n] {
			if b != '\n' {
				t.pending = append(t.pending, b)
				if len(t.pending) > components.MaxMessageBytes {
					return errors.New("任务事件过大")
				}
				continue
			}
			var e components.Event
			if err := components.Decode(bytes.NewReader(t.pending), &e); err != nil {
				return fmt.Errorf("任务事件无效: %w", err)
			}
			t.pending = t.pending[:0]
			if err := consume(e); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

// Windows can briefly deny sharing while a file is published or inspected by
// system software. Retry only that OS condition, never malformed JSON or ACL
// denials. The bounded delay remains below the normal one-second stop budget.
func retrySharing(op func() error) error {
	deadline := time.Now().Add(250 * time.Millisecond)
	for {
		err := op()
		if !sharingViolation(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openMailbox(path string) (*os.File, error) {
	var f *os.File
	err := retrySharing(func() error { var err error; f, err = os.Open(path); return err })
	return f, err
}
