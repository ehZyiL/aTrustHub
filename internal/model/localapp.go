package model

import (
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	LocalAppBrowser    = "browser"
	LocalAppTCPForward = "tcp_forward"
	LocalAppCapture    = "capture_tcp"
)

// LocalApp is a saved explicit-proxy launcher or a local TCP forwarding
// endpoint. These modes do not imply transparent capture of arbitrary software.
type LocalApp struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	PointID       string   `json:"pointId"`
	Mode          string   `json:"mode"`
	Executable    string   `json:"executable,omitempty"`
	Args          []string `json:"args,omitempty"`
	WorkDir       string   `json:"workDir,omitempty"`
	URL           string   `json:"url,omitempty"`
	RemoteAddress string   `json:"remoteAddress,omitempty"`
	ListenPort    int      `json:"listenPort,omitempty"`
}

func (a *LocalApp) Normalize() {
	a.ID = strings.TrimSpace(a.ID)
	a.Name = strings.TrimSpace(a.Name)
	a.PointID = strings.TrimSpace(a.PointID)
	a.Mode = strings.TrimSpace(a.Mode)
	a.Executable = strings.TrimSpace(a.Executable)
	a.WorkDir = strings.TrimSpace(a.WorkDir)
	a.URL = strings.TrimSpace(a.URL)
	a.RemoteAddress = strings.TrimSpace(a.RemoteAddress)
	if a.Mode == "" {
		a.Mode = LocalAppBrowser
	}
	if a.Mode == LocalAppBrowser && a.URL == "" {
		a.URL = "about:blank"
	}
}

// Validate leaves filesystem availability to Start, so configuration can still
// be edited after an application was moved or uninstalled.
func (a *LocalApp) Validate() error {
	if a.ID == "" {
		return errors.New("本机软件 ID 不能为空")
	}
	if a.Name == "" {
		return errors.New("名称不能为空")
	}
	if a.PointID == "" {
		return errors.New("请选择接入点")
	}
	if a.Executable != "" && !filepath.IsAbs(a.Executable) {
		return errors.New("可执行文件必须使用绝对路径")
	}
	if a.WorkDir != "" && !filepath.IsAbs(a.WorkDir) {
		return errors.New("工作目录必须使用绝对路径")
	}
	switch a.Mode {
	case LocalAppBrowser:
		// Arbitrary switches can override --proxy-server and the independent
		// profile. A later adapter can add an explicit allow-list if needed.
		if len(a.Args) != 0 {
			return errors.New("当前浏览器模式不支持自定义启动参数")
		}
		if a.URL == "" || a.URL == "about:blank" {
			return nil
		}
		u, err := url.Parse(a.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return errors.New("起始网址必须为 http://、https:// 或 about:blank")
		}
		if u.User != nil {
			return errors.New("起始网址不能包含用户名或密码")
		}
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return errors.New("起始网址端口必须在 1–65535 之间")
			}
		}
	case LocalAppCapture:
		if a.Executable == "" {
			return errors.New("请选择要启动的可执行文件")
		}
		if len(a.Args) > 256 {
			return errors.New("启动参数过多")
		}
		for _, arg := range a.Args {
			if len(arg) > 8192 || strings.ContainsRune(arg, 0) {
				return errors.New("启动参数无效或过长")
			}
		}
		if strings.ContainsRune(a.Executable, 0) || strings.ContainsRune(a.WorkDir, 0) {
			return errors.New("软件路径无效")
		}
		if a.URL != "" || a.RemoteAddress != "" || a.ListenPort != 0 {
			return errors.New("软件接管模式不使用浏览器网址或转发端口")
		}
	case LocalAppTCPForward:
		if a.ListenPort < 0 || a.ListenPort > 65535 {
			return errors.New("本地端口必须在 0–65535 之间，0 表示自动分配")
		}
		host, port, err := net.SplitHostPort(a.RemoteAddress)
		if err != nil || host == "" || strings.ContainsAny(host, " /?#@\\\t\r\n\x00") {
			return errors.New("远端地址必须为主机名或 IP 加端口，例如 db.internal:5432")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("远端端口必须在 1–65535 之间")
		}
		if len(a.Args) != 0 || a.Executable != "" || a.WorkDir != "" {
			return errors.New("TCP 转发模式仅创建本地端口，不启动外部程序")
		}
	default:
		return errors.New("不支持的本机软件接入方式")
	}
	return nil
}

func (c *Config) FindLocalApp(id string) *LocalApp {
	for i := range c.LocalApps {
		if c.LocalApps[i].ID == id {
			return &c.LocalApps[i]
		}
	}
	return nil
}

// Clone returns an independent configuration snapshot for editors and workers.
func (c Config) Clone() Config {
	out := c
	out.Points = append([]AccessPoint(nil), c.Points...)
	for i := range out.Points {
		out.Points[i].InternalDomains = append([]string(nil), c.Points[i].InternalDomains...)
		out.Points[i].DisabledApps = append([]string(nil), c.Points[i].DisabledApps...)
		if c.Points[i].Monitor != nil {
			v := *c.Points[i].Monitor
			out.Points[i].Monitor = &v
		}
	}
	out.LocalApps = append([]LocalApp(nil), c.LocalApps...)
	for i := range out.LocalApps {
		out.LocalApps[i].Args = append([]string(nil), c.LocalApps[i].Args...)
	}
	return out
}
