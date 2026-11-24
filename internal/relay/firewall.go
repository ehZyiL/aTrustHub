package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// FirewallGuidance is what this platform can honestly promise about the inbound
// rule the share port may need. It is a manual action: enabling a share never
// edits firewall rules quietly.
type FirewallGuidance struct {
	Platform string
	// Automatic is true only where this build can create and read back one
	// minimal rule on explicit user request.
	Automatic bool
	Lines     []string
}

// FirewallRule is the one rule this app manages. It is deliberately minimal:
// one program, one TCP port, one profile set, one local subnet.
type FirewallRule struct {
	// ID is the stable rule name, so cleanup touches only our own rule.
	ID          string `json:"id"`
	Name        string `json:"name"`
	ProgramPath string `json:"programPath"`
	Port        int    `json:"port"`
	Profile     string `json:"profile"`  // "private" or "private,domain"
	RemoteIP    string `json:"remoteIp"` // selected LAN subnet, e.g. 192.168.1.0/24
	CreatedAt   int64  `json:"createdAt"`
}

// FirewallRulePrefix is the only rule-name prefix this app may create or delete.
const FirewallRulePrefix = "ConnectHub-LANShare-"

// Validate checks the rule before anything is executed. The elevated helper runs
// the same checks on its side: the caller of a privileged operation is never
// trusted to have validated its own arguments.
func (r FirewallRule) Validate() error {
	if r.ID == "" || !strings.HasPrefix(r.ID, FirewallRulePrefix) {
		return errors.New("防火墙规则 ID 必须是本程序生成的标识")
	}
	if len(r.ID) > 128 {
		return errors.New("防火墙规则 ID 过长")
	}
	if !safeRuleID(r.ID) {
		return errors.New("防火墙规则 ID 含有非法字符")
	}
	if r.ProgramPath == "" {
		return errors.New("防火墙规则缺少程序路径")
	}
	if !absoluteProgramPath(r.ProgramPath) {
		return errors.New("防火墙规则的程序路径必须是绝对路径")
	}
	if strings.ContainsAny(r.ProgramPath, "\r\n\x00") {
		return errors.New("防火墙规则的程序路径包含非法字符")
	}
	if r.Port < 1 || r.Port > 65535 {
		return errors.New("防火墙规则端口无效")
	}
	if r.Profile != "private" && r.Profile != "private,domain" {
		return errors.New("首版只允许专用网络配置文件")
	}
	if r.RemoteIP != "" {
		_, network, err := net.ParseCIDR(r.RemoteIP)
		if err != nil {
			return errors.New("防火墙规则的局域网范围无效")
		}
		if ones, _ := network.Mask.Size(); ones == 0 {
			return errors.New("防火墙规则不能对任意地址放行")
		}
	}
	return nil
}

// safeRuleID restricts a rule name to characters that PowerShell's -DisplayName
// (a wildcard-capable parameter) cannot reinterpret, so a crafted id can never
// match or delete a rule this app did not create.
func safeRuleID(id string) bool {
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// absoluteProgramPath accepts the forms an absolute program path can take on the
// platform that executes the rule, so the same validation is meaningful when it
// runs in a test on another system.
func absoluteProgramPath(p string) bool {
	if filepath.IsAbs(p) {
		return true
	}
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0]
		return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	}
	return strings.HasPrefix(p, `\\`)
}

// Operation kinds the elevated helper accepts. It is a closed set: the helper is
// not a general firewall command runner.
const (
	FirewallOpApply  = "apply"
	FirewallOpQuery  = "query"
	FirewallOpDelete = "delete"
)

// FirewallOperation is one request to the elevated helper.
type FirewallOperation struct {
	OperationID string       `json:"operationId"`
	Op          string       `json:"op"`
	Rule        FirewallRule `json:"rule,omitempty"`
	RuleID      string       `json:"ruleId,omitempty"`
}

// Validate is the contract both sides enforce.
func (o FirewallOperation) Validate() error {
	if o.OperationID == "" || len(o.OperationID) > 128 {
		return errors.New("防火墙操作缺少标识")
	}
	switch o.Op {
	case FirewallOpApply:
		return o.Rule.Validate()
	case FirewallOpQuery, FirewallOpDelete:
		if o.RuleID == "" || !strings.HasPrefix(o.RuleID, FirewallRulePrefix) {
			return errors.New("防火墙操作只能针对本程序创建的规则")
		}
		if !safeRuleID(o.RuleID) {
			return errors.New("防火墙规则 ID 含有非法字符")
		}
		return nil
	default:
		return errors.New("不支持的防火墙操作")
	}
}

// Firewall outcomes. A caller must be able to tell "the user cancelled the
// prompt" from "the rule is in place", and "we could not read the rule back"
// from "the rule is absent".
const (
	FirewallCreated  = "created"
	FirewallPresent  = "present"
	FirewallAbsent   = "absent"
	FirewallRemoved  = "removed"
	FirewallFailed   = "failed"
	FirewallCanceled = "canceled"
	FirewallDenied   = "denied"
	FirewallTimeout  = "timeout"
)

// FirewallResult is the helper's answer. Outcome is authoritative; Detail is for
// the panel and the log.
type FirewallResult struct {
	OperationID string            `json:"operationId"`
	Op          string            `json:"op"`
	Outcome     string            `json:"outcome"`
	Rule        FirewallRule      `json:"rule,omitempty"`
	State       FirewallRuleState `json:"state,omitempty"`
	Detail      string            `json:"detail,omitempty"`
}

// Confirmed reports whether the outcome is a verified system state rather than a
// failed or unknown one.
func (r FirewallResult) Confirmed() bool {
	switch r.Outcome {
	case FirewallCreated, FirewallPresent, FirewallAbsent, FirewallRemoved:
		return true
	}
	return false
}

// firewallScriptAnswer is the helper script's JSON answer. It is decoded here so
// the wire shape and its quirks (BOM, CRLF) are covered by portable tests.
type firewallScriptAnswer struct {
	Outcome string `json:"outcome"`
	Detail  string `json:"detail"`
	State   *struct {
		Name      string `json:"name"`
		Direction string `json:"direction"`
		Action    string `json:"action"`
		Enabled   bool   `json:"enabled"`
		Profile   string `json:"profile"`
		Program   string `json:"program"`
		Protocol  string `json:"protocol"`
		LocalPort string `json:"localPort"`
		Remote    string `json:"remote"`
	} `json:"state"`
}

// utf8BOM is what Windows PowerShell 5.1 prepends to a file written with
// -Encoding UTF8. encoding/json rejects it, which used to turn a successful rule
// operation into "结果无法解析".
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ParseFirewallScriptAnswer decodes the helper's answer.
//
// The script writes BOM-less UTF-8, but a BOM is still tolerated: an older
// packaged helper (or a future edit) must not make a created rule look failed.
// UTF-16 output is reported as such instead of being silently misparsed.
func ParseFirewallScriptAnswer(data []byte) (FirewallResult, error) {
	if len(data) >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF)) {
		return FirewallResult{Outcome: FirewallFailed}, errors.New("防火墙结果使用了 UTF-16 编码，应为 UTF-8")
	}
	data = bytes.TrimPrefix(data, utf8BOM)
	data = bytes.TrimFunc(data, func(r rune) bool {
		return r == 0 || r == '\r' || r == '\n' || r == '\t' || r == ' '
	})
	if len(data) == 0 {
		return FirewallResult{Outcome: FirewallFailed}, errors.New("防火墙结果为空")
	}
	var answer firewallScriptAnswer
	if err := json.Unmarshal(data, &answer); err != nil {
		return FirewallResult{Outcome: FirewallFailed}, fmt.Errorf("防火墙结果无法解析：%w", err)
	}
	result := FirewallResult{Outcome: answer.Outcome, Detail: answer.Detail}
	if result.Outcome == "" {
		result.Outcome = FirewallFailed
	}
	if answer.State != nil {
		result.State = FirewallRuleState{
			Name:          answer.State.Name,
			Direction:     answer.State.Direction,
			Action:        answer.State.Action,
			Enabled:       answer.State.Enabled,
			Profile:       answer.State.Profile,
			Program:       answer.State.Program,
			Protocol:      answer.State.Protocol,
			LocalPort:     answer.State.LocalPort,
			RemoteAddress: answer.State.Remote,
		}
	}
	return result, nil
}

// FirewallRuleState is the full attribute set read back from the system. Only
// these fields decide whether a rule really matches what was requested; finding a
// rule with the right name is not enough.
type FirewallRuleState struct {
	Name          string `json:"name"`
	Direction     string `json:"direction"`
	Action        string `json:"action"`
	Enabled       bool   `json:"enabled"`
	Profile       string `json:"profile"`
	Program       string `json:"program"`
	Protocol      string `json:"protocol"`
	LocalPort     string `json:"localPort"`
	RemoteAddress string `json:"remoteAddress"`
}

// Matches reports why a read-back rule is not the rule that was requested.
func (s FirewallRuleState) Matches(rule FirewallRule) error {
	if s.Name != rule.ID {
		return fmt.Errorf("规则名称不符：%q", s.Name)
	}
	if !strings.EqualFold(strings.TrimSpace(s.Direction), "Inbound") {
		return fmt.Errorf("规则方向不符：%q", s.Direction)
	}
	if !strings.EqualFold(strings.TrimSpace(s.Action), "Allow") {
		return fmt.Errorf("规则动作不符：%q", s.Action)
	}
	if !s.Enabled {
		return errors.New("规则未启用")
	}
	if !profileMatches(s.Profile, rule.Profile) {
		return fmt.Errorf("规则配置文件不符：%q", s.Profile)
	}
	if !strings.EqualFold(filepath.Clean(s.Program), filepath.Clean(rule.ProgramPath)) {
		return fmt.Errorf("规则程序不符：%q", s.Program)
	}
	if !strings.EqualFold(strings.TrimSpace(s.Protocol), "TCP") {
		return fmt.Errorf("规则协议不符：%q", s.Protocol)
	}
	if strings.TrimSpace(s.LocalPort) != strconv.Itoa(rule.Port) {
		return fmt.Errorf("规则端口不符：%q", s.LocalPort)
	}
	if rule.RemoteIP != "" && !remoteMatches(s.RemoteAddress, rule.RemoteIP) {
		return fmt.Errorf("规则远端范围不符：%q", s.RemoteAddress)
	}
	return nil
}

// profileMatches compares the profile list as a set, since the system reports
// either "Private" or "Domain, Private" style values.
func profileMatches(reported, want string) bool {
	normalize := func(v string) map[string]bool {
		out := map[string]bool{}
		for _, part := range strings.FieldsFunc(strings.ToLower(v), func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		}) {
			if part != "" {
				out[part] = true
			}
		}
		return out
	}
	got, expected := normalize(reported), normalize(want)
	if len(expected) != len(got) {
		return false
	}
	for k := range expected {
		if !got[k] {
			return false
		}
	}
	return true
}

// remoteMatches accepts the several shapes the system uses for "the local
// subnet": the exact CIDR, or an address plus mask.
func remoteMatches(reported, want string) bool {
	reported = strings.TrimSpace(reported)
	if reported == "" {
		return false
	}
	if reported == want {
		return true
	}
	if networksOverlap(reported, want) {
		return true
	}
	return false
}

func networksOverlap(a, b string) bool {
	na, okA := parseNetwork(a)
	nb, okB := parseNetwork(b)
	return okA && okB && na.String() == nb.String()
}

// parseNetwork accepts both CIDR forms the system may report: a prefix length or
// a dotted mask.
func parseNetwork(s string) (*net.IPNet, bool) {
	if _, n, err := net.ParseCIDR(strings.TrimSpace(s)); err == nil {
		return n, true
	}
	ipPart, maskPart, found := strings.Cut(strings.TrimSpace(s), "/")
	if !found {
		return nil, false
	}
	ip := net.ParseIP(ipPart).To4()
	maskIP := net.ParseIP(maskPart).To4()
	if ip == nil || maskIP == nil {
		return nil, false
	}
	mask := net.IPMask(maskIP)
	if ones, bits := mask.Size(); bits != 32 || ones == 0 {
		return nil, false
	}
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, true
}

// FirewallJournalEntry is one rule this app is responsible for. It is written
// before the rule exists and removed only after the system confirms it is gone,
// so a crash, a cancelled prompt or a late success always leaves a trace.
type FirewallJournalEntry struct {
	Rule FirewallRule `json:"rule"`
	// OperationID ties the record to the action that created it, so a success
	// arriving after the user turned sharing off can be revoked.
	OperationID string `json:"operationId,omitempty"`
	// State is pending (create in flight), confirmed (verified present),
	// removing (delete in flight) or failed (last action failed, retry needed).
	State     string `json:"state"`
	UpdatedAt int64  `json:"updatedAt"`
	LastError string `json:"lastError,omitempty"`
}

// Journal states.
const (
	FirewallEntryPending   = "pending"
	FirewallEntryConfirmed = "confirmed"
	FirewallEntryRemoving  = "removing"
	FirewallEntryFailed    = "failed"
)

// FirewallJournal is the recovery record of the data directory.
type FirewallJournal struct {
	Schema  int                    `json:"schema"`
	Entries []FirewallJournalEntry `json:"entries"`
}

// FirewallJournalSchema is the current format. Schema 1 stored bare rules.
const FirewallJournalSchema = 2

// FirewallJournalPath is the journal of the data directory.
func FirewallJournalPath(dir string) string {
	return filepath.Join(dir, "lan-share-firewall.json")
}

// legacyFirewallJournal is the schema-1 shape, kept only to migrate it.
type legacyFirewallJournal struct {
	Schema  int            `json:"schema"`
	Rules   []FirewallRule `json:"rules"`
	Pending bool           `json:"pending,omitempty"`
}

// LoadFirewallJournal reads the record. A missing file is not an error.
func LoadFirewallJournal(dir string) (*FirewallJournal, error) {
	data, err := os.ReadFile(FirewallJournalPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return &FirewallJournal{Schema: FirewallJournalSchema}, nil
	}
	if err != nil {
		return nil, err
	}
	var probe struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("防火墙恢复记录无法读取：%w", err)
	}
	switch probe.Schema {
	case FirewallJournalSchema:
		var journal FirewallJournal
		if err := json.Unmarshal(data, &journal); err != nil {
			return nil, fmt.Errorf("防火墙恢复记录无法读取：%w", err)
		}
		return &journal, nil
	case 1:
		var legacy legacyFirewallJournal
		if err := json.Unmarshal(data, &legacy); err != nil {
			return nil, fmt.Errorf("防火墙恢复记录无法读取：%w", err)
		}
		journal := &FirewallJournal{Schema: FirewallJournalSchema}
		for _, rule := range legacy.Rules {
			// Its pending flag was global, so an unconfirmed schema-1 rule is
			// recorded as such and will be verified on the next start.
			state := FirewallEntryConfirmed
			if legacy.Pending {
				state = FirewallEntryPending
			}
			journal.Entries = append(journal.Entries, FirewallJournalEntry{Rule: rule, State: state})
		}
		return journal, nil
	default:
		return nil, errors.New("防火墙恢复记录版本不受支持")
	}
}

// Save writes the record atomically.
func (j *FirewallJournal) Save(dir string) error {
	j.Schema = FirewallJournalSchema
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	path := FirewallJournalPath(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Pending reports whether any recorded rule still needs a confirmed system state.
func (j *FirewallJournal) Pending() bool {
	for _, e := range j.Entries {
		if e.State != FirewallEntryConfirmed {
			return true
		}
	}
	return false
}

// Find returns the entry of a rule id.
func (j *FirewallJournal) Find(id string) *FirewallJournalEntry {
	for i := range j.Entries {
		if j.Entries[i].Rule.ID == id {
			return &j.Entries[i]
		}
	}
	return nil
}

// Put records or updates one entry, then persists.
func (j *FirewallJournal) Put(dir string, entry FirewallJournalEntry) error {
	entry.UpdatedAt = time.Now().Unix()
	replaced := false
	for i := range j.Entries {
		if j.Entries[i].Rule.ID == entry.Rule.ID {
			j.Entries[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		j.Entries = append(j.Entries, entry)
	}
	return j.Save(dir)
}

// Remove forgets a rule after the system confirmed it is gone.
func (j *FirewallJournal) Remove(dir, id string) error {
	kept := make([]FirewallJournalEntry, 0, len(j.Entries))
	for _, e := range j.Entries {
		if e.Rule.ID != id {
			kept = append(kept, e)
		}
	}
	j.Entries = kept
	return j.Save(dir)
}

// NewFirewallRuleID makes a stable, recognisable rule id for a share instance.
func NewFirewallRuleID(port int, now time.Time) string {
	return fmt.Sprintf("%s%d-%d", FirewallRulePrefix, port, now.UnixNano())
}

// SubnetOfAddress returns the subnet of the local interface that holds ip, using
// that interface's real mask. A hardcoded /24 would either let in a neighbour
// network or exclude colleagues on a /16 or /23 office LAN.
func SubnetOfAddress(ip string) (string, error) {
	target := net.ParseIP(strings.TrimSpace(ip)).To4()
	if target == nil {
		return "", errors.New("分享地址不是 IPv4")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if !ipnet.IP.Equal(target) {
				continue
			}
			network := &net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}
			return network.String(), nil
		}
	}
	return "", errors.New("找不到该地址所在网卡的子网掩码")
}

// subnetOfMask is the pure part of SubnetOfAddress, so the mask arithmetic can
// be tested without the host's network layout.
func subnetOfMask(ip string, mask net.IPMask) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip)).To4()
	if parsed == nil {
		return "", errors.New("分享地址不是 IPv4")
	}
	if ones, bits := mask.Size(); bits != 32 || ones == 0 {
		return "", errors.New("网卡子网掩码无效")
	}
	return (&net.IPNet{IP: parsed.Mask(mask), Mask: mask}).String(), nil
}

// LANSubnetOf keeps the /24 helper for callers that only have an address and no
// interface information. Rules created from it are marked accordingly; the app
// prefers SubnetOfAddress.
func LANSubnetOf(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip)).To4()
	if parsed == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", parsed[0], parsed[1], parsed[2])
}
