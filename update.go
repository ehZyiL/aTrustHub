package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/egoist/mygo"
)

// projectRepo is the GitHub repository this build comes from.
const projectRepo = "ehZyiL/aTrustHub"

// projectURL is the repository home page, opened by the footer icon.
const projectURL = "https://github.com/" + projectRepo

// ghMirrorPrefix is the mirror that serves github.com pages when the direct
// site is unreachable (the office network blocks it).
const ghMirrorPrefix = "https://gh-proxy.com/"

// updateInfo describes a release newer than this build.
type updateInfo struct {
	Version string // without the leading "v"
	URL     string // release page
	Notes   string // first line of the release body
	Source  string // which endpoint answered
}

// releaseSources are tried in order. The direct GitHub API usually works at
// home but is blocked or very slow from the office network, so the mirrors
// behind it are what makes the check useful there.
func releaseSources() []string {
	api := "https://api.github.com/repos/" + projectRepo + "/releases/latest"
	// Reachability measured on the office machine: api.github.com and
	// gh-proxy.com answer; mirror.ghproxy.com times out and ghproxy.net /
	// ghfast.top reply 403, so they are not worth a request. The jsDelivr
	// family serves the version out of mygo.json and is the fallback that
	// actually works behind the Great Firewall.
	manifest := projectRepo + "@main/mygo.json"
	return []string{
		api,
		"https://gh-proxy.com/" + api,
		"https://testingcf.jsdelivr.net/gh/" + manifest,
		"https://gcore.jsdelivr.net/gh/" + manifest,
		"https://cdn.jsdelivr.net/gh/" + manifest,
		"https://raw.githubusercontent.com/" + projectRepo + "/main/mygo.json",
	}
}

// startUpdateScheduler runs the background update checker.
// It checks once shortly after launch, and then every 24 hours, if AutoCheckUpdate is enabled.
func (a *app) startUpdateScheduler() {
	go func() {
		// 启动后延迟 10 秒，等待网络初始化与系统 DNS 就绪
		select {
		case <-a.tickersStop:
			return
		case <-time.After(10 * time.Second):
		}

		if a.configForBackground().Settings.AutoCheckUpdate {
			a.checkForUpdate(false)
		}

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-a.tickersStop:
				return
			case <-ticker.C:
				if a.configForBackground().Settings.AutoCheckUpdate {
					a.checkForUpdate(false)
				}
			}
		}
	}()
}

// checkForUpdate asks GitHub for the newest release.
// When manual is true, it notifies the user via toast even if no update is found or on error.
// When manual is false, it runs silently in the background and only alerts if an update is found.
func (a *app) checkForUpdate(manual bool) {
	if !a.updateChecking.CompareAndSwap(false, true) {
		if manual && a.win != nil {
			a.win.Update(func() {
				a.toast = "正在检查更新，请稍候…"
			})
		}
		return
	}
	defer a.updateChecking.Store(false)

	if manual && a.win != nil {
		a.win.Update(func() {
			a.toast = "正在检查更新…"
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 5 * time.Second}
	var failures []string
	noHost := 0
	for i, url := range releaseSources() {
		direct := i == 0
		info, err := fetchLatest(ctx, client, url)
		if err != nil {
			if isResolveError(err) {
				noHost++
			}
			failures = append(failures, shortHost(url)+": "+err.Error())
			continue
		}
		if info == nil {
			continue
		}
		// 直达 GitHub 成功，说明浏览器也打得开；靠镜像才成功时，
		// 「GitHub 图标」也应当跳到镜像上，否则点了是白屏。
		a.markGitHubReach(direct)
		if !versionGreater(info.Version, appBuild) {
			a.noteUpdate("已是最新版本 " + appBuild + "（来源 " + info.Source + "）")
			if manual && a.win != nil {
				a.win.Update(func() {
					a.toast = "当前已是最新版本 " + appBuild
				})
			}
			return
		}
		if a.win != nil {
			a.win.Update(func() {
				a.update = info
				a.toast = fmt.Sprintf("发现新版本 v%s，点关于页按钮下载", info.Version)
			})
		}
		a.noteUpdate(fmt.Sprintf("发现新版本 v%s（当前 v%s，来源 %s）", info.Version, appBuild, info.Source))
		return
	}
	errMsg := "检查更新失败：" + strings.Join(failures, " ｜ ")
	if noHost == len(failures) && len(failures) > 0 {
		errMsg = "检查更新失败：网络暂时无法解析域名，请稍后重试"
	}
	a.noteUpdate(errMsg)
	if manual && a.win != nil {
		a.win.Update(func() {
			a.toast = errMsg
		})
	}
	// 启动时我们刚把系统 DNS 还回去，第一次查询常常还没通。别就此放弃，
	// 一分钟后再试一次——总失败时也说明不了 GitHub 不可达，图标仍按直连。
	if !manual && a.updateRetried.CompareAndSwap(false, true) {
		time.AfterFunc(90*time.Second, func() {
			a.noteUpdate("重试检查更新")
			a.checkForUpdate(false)
		})
	}
}

// markGitHubReach remembers whether github.com itself answered, which decides
// where the footer icon sends the browser.
func (a *app) markGitHubReach(direct bool) {
	if a.win != nil {
		a.win.Update(func() { a.ghReachable = direct })
	} else {
		a.ghReachable = direct
	}
	if !direct {
		a.noteUpdate("github.com 直连不可用，链接改走镜像 " + ghMirrorPrefix)
	}
}

// githubPage returns a github.com page URL that this machine can open: the
// mirror prefix is added when the direct site did not answer.
func (a *app) githubPage(url string) string {
	if a.ghReachable {
		return url
	}
	return ghMirrorPrefix + url
}

// noteUpdate records the outcome in the app log without alarming the user.
func (a *app) noteUpdate(line string) {
	if a.bus != nil {
		a.bus.Add("app", "更新检查："+line)
	}
}

// fetchLatest reads one endpoint and returns the release it describes, or nil
// when the answer is unusable.
func fetchLatest(ctx context.Context, client *http.Client, url string) (*updateInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "aTrustHub/"+appBuild)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body := make([]byte, 1<<20)
	n, _ := resp.Body.Read(body)
	raw := strings.TrimSpace(string(body[:n]))
	if raw == "" {
		return nil, fmt.Errorf("空响应")
	}
	if strings.Contains(url, "releases/latest") {
		return parseRelease(raw, url)
	}
	return parseManifest(raw, url)
}

// parseRelease reads GitHub's release JSON.
func parseRelease(raw, url string) (*updateInfo, error) {
	var r struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Body    string `json:"body"`
	}
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("解析发布：%w", err)
	}
	v := strings.TrimPrefix(strings.TrimSpace(r.TagName), "v")
	if v == "" {
		return nil, fmt.Errorf("没有版本号")
	}
	return &updateInfo{
		Version: v,
		URL:     orDefault(r.HTMLURL, projectURL+"/releases/tag/v"+v),
		Notes:   firstLine(r.Body),
		Source:  shortHost(url),
	}, nil
}

// parseManifest falls back to the version field of mygo.json served through a
// CDN, which is bumped with every release.
func parseManifest(raw, url string) (*updateInfo, error) {
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("解析清单：%w", err)
	}
	v := strings.TrimPrefix(strings.TrimSpace(m.Version), "v")
	if v == "" {
		return nil, fmt.Errorf("清单里没有版本号")
	}
	return &updateInfo{
		Version: v,
		URL:     projectURL + "/releases/tag/v" + v,
		Source:  shortHost(url),
	}, nil
}

// versionGreater reports whether a is a newer release than b.
// It complies with semantic versioning:
// 1. Strips leading "v" if present.
// 2. Compares major.minor.patch numeric parts. Missing parts count as 0.
// 3. If numeric parts are equal, a release without prerelease suffix is strictly
//    newer than one with a prerelease suffix (e.g. "0.1.0" > "0.1.0-dev.11").
// 4. If both have prerelease suffixes, compare them.
func versionGreater(a, b string) bool {
	va, preA := splitPrerelease(strings.TrimPrefix(strings.TrimSpace(a), "v"))
	vb, preB := splitPrerelease(strings.TrimPrefix(strings.TrimSpace(b), "v"))
	pa, pb := strings.Split(va, "."), strings.Split(vb, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := num(part(pa, i)), num(part(pb, i))
		if x != y {
			return x > y
		}
	}
	// Numeric parts are identical.
	// Standard SemVer: 1.0.0 is greater than 1.0.0-alpha / 1.0.0-dev
	if preA == "" && preB != "" {
		return true
	}
	if preA != "" && preB == "" {
		return false
	}
	if preA != "" && preB != "" {
		return preA > preB
	}
	return false
}

func splitPrerelease(v string) (main, pre string) {
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func part(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "0"
}

// num reads the leading integer of a version part, ignoring any suffix.
func num(s string) int {
	digits := strings.TrimFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	if i := strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		digits = digits[:i]
	}
	v, err := strconv.Atoi(digits)
	if err != nil {
		return 0
	}
	return v
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len([]rune(s)) > 80 {
		s = string([]rune(s)[:80]) + "…"
	}
	return s
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// shortHost names an endpoint in one word for the log.
func shortHost(url string) string {
	rest := url
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "api.github.com" {
		return "GitHub"
	}
	return rest
}

// openProject opens the repository page in the default browser.
func (a *app) openProject() {
	if err := mygo.Shell.OpenExternal(a.githubPage(projectURL)); err != nil {
		a.toast = "打不开 GitHub：" + err.Error()
	}
}

// openUpdate opens the release page of the newer version, falling back to the
// repository when the check only knew a version number.
func (a *app) openUpdate() {
	url := projectURL + "/releases"
	if a.update != nil && a.update.URL != "" {
		url = a.update.URL
	}
	if err := mygo.Shell.OpenExternal(a.githubPage(url)); err != nil {
		a.toast = "打不开下载页：" + err.Error()
	}
}

// isResolveError reports whether a request failed before reaching the host,
// which says nothing about GitHub being blocked — it usually means the machine
// has no working DNS yet.
func isResolveError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "lookup ") ||
		strings.Contains(msg, "server misbehaving")
}
