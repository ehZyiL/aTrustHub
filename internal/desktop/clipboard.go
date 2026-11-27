package desktop

import (
	"fmt"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/transfer"
	"strings"
)

func (a *app) copyText(text string) {
	if text == "" {
		return
	}
	if err := mygo.Clipboard.Write(transfer.TextData(text)); err != nil {
		a.toast = "复制失败：" + err.Error()
		a.invalidate()
		return
	}
	// Keep the notice short: showing the copied text itself made the toast
	// cover the window when a whole log was copied.
	if lines := strings.Count(text, "\n") + 1; lines > 1 {
		a.toast = fmt.Sprintf("已复制 %d 行", lines)
	} else {
		a.toast = "已复制：" + shortText(text, 40)
	}
	a.invalidate()
}

// shortText clips s for a one-line notice.
func shortText(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len([]rune(s)) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "…"
}
