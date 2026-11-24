package relay

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// FirewallExecutor performs the three privileged operations. On Windows it is
// the elevated helper; everywhere else it refuses, because no rule is created on
// those platforms in this version.
type FirewallExecutor interface {
	Run(ctx context.Context, op FirewallOperation) (FirewallResult, error)
}

// ErrFirewallUnsupported means this platform has no automated rule handling.
var ErrFirewallUnsupported = errors.New("当前平台不支持自动创建防火墙规则，请按提示手动放行")

// Rules owns every rule this app creates: the journal that records them and the
// serialized calls to the elevated helper.
//
// It is deliberately the single place that creates, verifies and removes rules.
// Firewall rules outlive the process, so "who cleans this up" has to be one
// answer for every lifecycle path (disable, quit, source loss, node deletion and
// crash recovery), not a call bolted onto the disable button.
type Rules struct {
	dir  string
	exec FirewallExecutor
	logf func(string, ...any)

	// mu serialises journal read-modify-write and helper calls, so two paths
	// (for example a user click and an exit cleanup) cannot fight over the file.
	mu sync.Mutex
	// canceled holds operation ids whose result must be revoked on arrival: the
	// user turned sharing off while the elevation prompt was still open.
	canceled map[string]bool
}

// NewRules builds the coordinator. dir is the app data directory.
func NewRules(dir string, exec FirewallExecutor, logf func(string, ...any)) *Rules {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Rules{dir: dir, exec: exec, logf: logf, canceled: map[string]bool{}}
}

// Cancel marks an in-flight operation as unwanted. If it succeeds after this, the
// rule is deleted instead of being confirmed: a closed share must never be
// reopened by a prompt that was answered late.
func (r *Rules) Cancel(operationID string) {
	if operationID == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.canceled[operationID] = true
}

// Apply creates one rule. The journal is written before the prompt so a crash
// mid-prompt still leaves enough to clean up, and the rule is only confirmed
// after the helper read back the full attribute set.
func (r *Rules) Apply(ctx context.Context, rule FirewallRule) (FirewallResult, error) {
	if err := rule.Validate(); err != nil {
		return FirewallResult{Outcome: FirewallFailed, Detail: err.Error()}, err
	}
	opID := rule.ID
	op := FirewallOperation{OperationID: opID, Op: FirewallOpApply, Rule: rule}

	r.mu.Lock()
	journal, err := LoadFirewallJournal(r.dir)
	if err != nil {
		r.mu.Unlock()
		return FirewallResult{Outcome: FirewallFailed, Detail: err.Error()}, err
	}
	if err := journal.Put(r.dir, FirewallJournalEntry{
		Rule: rule, OperationID: opID, State: FirewallEntryPending,
	}); err != nil {
		r.mu.Unlock()
		return FirewallResult{Outcome: FirewallFailed, Detail: err.Error()}, fmt.Errorf("防火墙恢复记录无法写入：%w", err)
	}
	r.mu.Unlock()

	result, err := r.exec.Run(ctx, op)
	result.OperationID = opID
	result.Op = FirewallOpApply
	result.Rule = rule

	r.mu.Lock()
	canceled := r.canceled[opID]
	delete(r.canceled, opID)
	r.mu.Unlock()

	if canceled {
		// The user closed the share while the prompt was open. Even a verified
		// creation is not wanted any more.
		if result.Outcome == FirewallCreated || result.Outcome == FirewallPresent {
			if removeErr := r.Remove(ctx, rule); removeErr != nil {
				r.record(rule, opID, FirewallEntryFailed, "关闭共享后规则未能删除："+removeErr.Error())
			}
			return FirewallResult{OperationID: opID, Op: FirewallOpApply, Outcome: FirewallCanceled, Rule: rule, Detail: "共享已关闭，规则已撤销"}, nil
		}
		r.dropIfAbsent(rule.ID, result)
		return FirewallResult{OperationID: opID, Op: FirewallOpApply, Outcome: FirewallCanceled, Rule: rule, Detail: "共享已关闭，未创建规则"}, nil
	}

	switch {
	case err != nil:
		r.record(rule, opID, FirewallEntryFailed, err.Error())
		return result, err
	case result.Outcome == FirewallCreated || result.Outcome == FirewallPresent:
		if err := result.State.Matches(rule); err != nil {
			// A rule with the right name but different attributes is not the
			// rule that was requested. Never report success from a name match.
			r.record(rule, opID, FirewallEntryFailed, "规则属性不符："+err.Error())
			return FirewallResult{OperationID: opID, Op: FirewallOpApply, Outcome: FirewallFailed, Rule: rule, State: result.State,
				Detail: "规则属性不符：" + err.Error()}, nil
		}
		if err := r.recordErr(rule, opID, FirewallEntryConfirmed, ""); err != nil {
			return result, fmt.Errorf("规则已创建，但恢复记录未能确认：%w", err)
		}
		result.Outcome = FirewallCreated
		return result, nil
	default:
		// Canceled, denied, timeout or failure: the system state is unknown, so
		// the journal entry stays pending for the next start to verify.
		r.record(rule, opID, FirewallEntryPending, result.Detail)
		return result, nil
	}
}

// Remove deletes one rule and forgets it only after the system confirms it is
// gone. A failure keeps the record so the next start can retry.
func (r *Rules) Remove(ctx context.Context, rule FirewallRule) error {
	if err := (FirewallOperation{OperationID: rule.ID, Op: FirewallOpDelete, RuleID: rule.ID}).Validate(); err != nil {
		return err
	}
	op := FirewallOperation{OperationID: rule.ID, Op: FirewallOpDelete, RuleID: rule.ID}

	r.mu.Lock()
	if err := r.markEntry(rule, FirewallEntryRemoving, ""); err != nil {
		r.mu.Unlock()
		return err
	}
	r.mu.Unlock()

	result, err := r.exec.Run(ctx, op)
	if err != nil {
		r.record(rule, rule.ID, FirewallEntryFailed, err.Error())
		return err
	}
	switch result.Outcome {
	case FirewallRemoved, FirewallAbsent:
		r.mu.Lock()
		defer r.mu.Unlock()
		journal, loadErr := LoadFirewallJournal(r.dir)
		if loadErr != nil {
			return loadErr
		}
		return journal.Remove(r.dir, rule.ID)
	case FirewallCanceled, FirewallDenied, FirewallTimeout:
		r.record(rule, rule.ID, FirewallEntryFailed, "删除未完成："+result.Outcome)
		return fmt.Errorf("删除防火墙规则需要系统授权：%s", result.Outcome)
	default:
		r.record(rule, rule.ID, FirewallEntryFailed, result.Detail)
		return fmt.Errorf("防火墙规则仍然存在，清理未完成")
	}
}

// Reconcile makes the journal match the rules that should exist now. It never
// creates a rule: creating one needs an explicit user action and a UAC prompt.
//
// desired is the exact set that a running share justifies. Everything else this
// app recorded is removed, because the share it belonged to is no longer running
// in that shape. Matching rules are kept, so a restart does not need a new prompt.
func (r *Rules) Reconcile(ctx context.Context, desired []FirewallRule) (kept int, errs []error) {
	r.mu.Lock()
	journal, err := LoadFirewallJournal(r.dir)
	if err != nil {
		r.mu.Unlock()
		return 0, []error{err}
	}
	// Copy: the journal is reloaded by the helpers below.
	var stale []FirewallRule
	for _, entry := range journal.Entries {
		if wants(desired, entry.Rule) {
			kept++
			continue
		}
		stale = append(stale, entry.Rule)
		if entry.State != FirewallEntryConfirmed {
			// A create may still be sitting behind an elevation prompt. The
			// share no longer wants it, so a late success must be revoked
			// instead of being confirmed. Without this, pausing a share could
			// leave a rule behind after the prompt was answered.
			r.canceled[entry.OperationID] = true
		}
	}
	r.mu.Unlock()

	for _, rule := range stale {
		if rmErr := r.Remove(ctx, rule); rmErr != nil {
			errs = append(errs, rmErr)
			continue
		}
		r.logf("局域网分享：已清理本程序的防火墙规则 %s", rule.ID)
	}
	return kept, errs
}

// Recover verifies every recorded rule against the system before the app resumes
// a share. A rule that exists and matches is reusable; a rule that is gone is
// forgotten; a rule that exists but no longer matches is deleted so it cannot
// keep an old scope open.
//
// It never widens a previous authorization: if the current share needs a
// different scope, the entry is removed and the user is asked again.
func (r *Rules) Recover(ctx context.Context, desired []FirewallRule) (kept []FirewallRule, errs []error) {
	r.mu.Lock()
	journal, err := LoadFirewallJournal(r.dir)
	if err != nil {
		r.mu.Unlock()
		return nil, []error{err}
	}
	entries := append([]FirewallJournalEntry(nil), journal.Entries...)
	r.mu.Unlock()

	for _, entry := range entries {
		rule := entry.Rule
		result, runErr := r.exec.Run(ctx, FirewallOperation{OperationID: rule.ID, Op: FirewallOpQuery, RuleID: rule.ID})
		switch {
		case runErr != nil:
			errs = append(errs, fmt.Errorf("%s：无法核对防火墙规则：%w", rule.ID, runErr))
			continue
		case result.Outcome == FirewallAbsent:
			r.mu.Lock()
			if j, loadErr := LoadFirewallJournal(r.dir); loadErr == nil {
				_ = j.Remove(r.dir, rule.ID)
			}
			r.mu.Unlock()
			continue
		case result.Outcome != FirewallPresent:
			errs = append(errs, fmt.Errorf("%s：防火墙规则状态未知（%s）", rule.ID, result.Outcome))
			continue
		}
		if matchErr := result.State.Matches(rule); matchErr != nil || !wants(desired, rule) {
			if rmErr := r.Remove(ctx, rule); rmErr != nil {
				errs = append(errs, rmErr)
			}
			continue
		}
		kept = append(kept, rule)
	}
	return kept, errs
}

// Pending reports the rules that still need a verified system state, for the
// panel and the startup log.
func (r *Rules) Pending() []FirewallJournalEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	journal, err := LoadFirewallJournal(r.dir)
	if err != nil {
		return nil
	}
	var out []FirewallJournalEntry
	for _, e := range journal.Entries {
		if e.State != FirewallEntryConfirmed {
			out = append(out, e)
		}
	}
	return out
}

// wants reports whether rule is exactly one of the rules that should exist. The
// comparison is on the full identity, not just the port.
func wants(desired []FirewallRule, rule FirewallRule) bool {
	for _, d := range desired {
		if d.ID == rule.ID && d.Port == rule.Port && d.RemoteIP == rule.RemoteIP &&
			d.Profile == rule.Profile && d.ProgramPath == rule.ProgramPath {
			return true
		}
	}
	return false
}

// recordErr updates one journal entry and reports a write failure.
func (r *Rules) recordErr(rule FirewallRule, opID, state, lastError string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.markEntryLocked(rule, opID, state, lastError)
}

// record updates one journal entry.
func (r *Rules) record(rule FirewallRule, opID, state, lastError string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.markEntryLocked(rule, opID, state, lastError)
}

func (r *Rules) markEntry(rule FirewallRule, state, lastError string) error {
	return r.markEntryLocked(rule, rule.ID, state, lastError)
}

func (r *Rules) markEntryLocked(rule FirewallRule, opID, state, lastError string) error {
	journal, err := LoadFirewallJournal(r.dir)
	if err != nil {
		return err
	}
	entry := FirewallJournalEntry{Rule: rule, OperationID: opID, State: state, LastError: lastError}
	return journal.Put(r.dir, entry)
}

// dropIfAbsent forgets a rule that the system says does not exist.
func (r *Rules) dropIfAbsent(id string, result FirewallResult) {
	if result.Outcome != FirewallAbsent {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	journal, err := LoadFirewallJournal(r.dir)
	if err != nil {
		return
	}
	_ = journal.Remove(r.dir, id)
}

// FirewallOpBudget is how long one elevated operation may take, including the
// time the user spends deciding on the UAC prompt.
const FirewallOpBudget = 2 * time.Minute

// FirewallShutdownBudget bounds how long quitting waits for a rule cleanup. An
// unfinished cleanup keeps its journal entry and is retried on the next start;
// quitting must never hang on an unanswered elevation prompt.
const FirewallShutdownBudget = 5 * time.Second
