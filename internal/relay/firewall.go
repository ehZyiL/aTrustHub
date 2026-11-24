package relay

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// Validate checks the rule before anything is executed.
func (r FirewallRule) Validate() error {
	if r.ID == "" || !strings.HasPrefix(r.ID, "ConnectHub-LANShare-") {
		return errors.New("防火墙规则 ID 必须是本程序生成的标识")
	}
	if r.ProgramPath == "" {
		return errors.New("防火墙规则缺少程序路径")
	}
	if r.Port < 1 || r.Port > 65535 {
		return errors.New("防火墙规则端口无效")
	}
	if r.Profile != "private" && r.Profile != "private,domain" {
		return errors.New("首版只允许专用网络配置文件")
	}
	if r.RemoteIP != "" {
		if _, _, err := net.ParseCIDR(r.RemoteIP); err != nil {
			return errors.New("防火墙规则的局域网范围无效")
		}
	}
	return nil
}

// FirewallJournal is the recovery record: written before the rule is created so
// a crash still leaves enough to remove it on the next start.
type FirewallJournal struct {
	Schema int            `json:"schema"`
	Rules  []FirewallRule `json:"rules"`
	// Pending is true while a create/delete has not been confirmed, so the next
	// start knows to verify instead of assuming.
	Pending bool `json:"pending,omitempty"`
}

// FirewallJournalPath is the journal of the data directory.
func FirewallJournalPath(dir string) string {
	return filepath.Join(dir, "lan-share-firewall.json")
}

// LoadFirewallJournal reads the record. A missing file is not an error.
func LoadFirewallJournal(dir string) (*FirewallJournal, error) {
	data, err := os.ReadFile(FirewallJournalPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return &FirewallJournal{Schema: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var journal FirewallJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return nil, fmt.Errorf("防火墙恢复记录无法读取：%w", err)
	}
	if journal.Schema != 1 {
		return nil, errors.New("防火墙恢复记录版本不受支持")
	}
	return &journal, nil
}

// Save writes the record atomically.
func (j *FirewallJournal) Save(dir string) error {
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

// Add records a rule as pending before it exists, then confirms it.
func (j *FirewallJournal) Add(dir string, rule FirewallRule) error {
	j.Rules = append(j.Rules, rule)
	j.Pending = true
	return j.Save(dir)
}

// Confirm clears the pending flag after a successful read-back.
func (j *FirewallJournal) Confirm(dir string) error {
	j.Pending = false
	return j.Save(dir)
}

// Remove forgets a rule after it has been deleted.
func (j *FirewallJournal) Remove(dir, id string) error {
	kept := make([]FirewallRule, 0, len(j.Rules))
	for _, r := range j.Rules {
		if r.ID != id {
			kept = append(kept, r)
		}
	}
	j.Rules = kept
	return j.Save(dir)
}

// NewFirewallRuleID makes a stable, recognisable rule id for a share instance.
func NewFirewallRuleID(port int, now time.Time) string {
	return fmt.Sprintf("ConnectHub-LANShare-%d-%d", port, now.UnixNano())
}

// LANSubnetOf returns the /24 (or the interface's own mask) around ip, so a rule
// can be limited to the user's own network instead of "any".
func LANSubnetOf(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip)).To4()
	if parsed == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", parsed[0], parsed[1], parsed[2])
}
