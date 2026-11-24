package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ehzyil/connect-hub/internal/attribution"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// RelayKnownSchema is the cache format version.
const RelayKnownSchema = 1

// RelayKnownMaxBytes bounds one point's attribution cache. An oversized cache is
// an error, never silently truncated: losing history could let a known managed
// target fall back to the original network.
const RelayKnownMaxBytes = 4 << 20

// ErrRelayKnownCorrupt means the cache exists but cannot be trusted.
var ErrRelayKnownCorrupt = errors.New("局域网分享的历史归属缓存损坏")

// ErrRelayKnownStaleSource means the snapshot came from a share identity the
// node no longer has: the node was re-imported, replaced or deleted while a
// session was still running. A late callback must not rebuild the cache.
var ErrRelayKnownStaleSource = errors.New("局域网分享的历史归属来源与当前节点不一致")

// RelaySource is the authenticated identity a resource snapshot came from. It is
// verified against the stored node, so a late snapshot from a previous share
// cannot be written under a node that has since been re-imported.
type RelaySource struct {
	ShareID     string
	Fingerprint string
	// Label is for diagnostics only; it is never used for a decision.
	Label string
}

// RelayKnown is the attribution cache of one imported share. It only ever stops
// automatic direct dialing; it never authorizes a connection.
type RelayKnown struct {
	Schema      int                         `json:"schema"`
	PointID     string                      `json:"pointId"`
	Source      string                      `json:"source"`
	ShareID     string                      `json:"shareId,omitempty"`
	Fingerprint string                      `json:"fingerprint,omitempty"`
	SavedAt     int64                       `json:"savedAt"`
	Resources   *workeripc.ResourceSnapshot `json:"resources"`
}

// RelayKnownPath is where a point's cache lives. The directory is private to the
// user and the file name comes from the local point id, never from a peer name.
func (s *Store) RelayKnownPath(pointID string) string {
	return filepath.Join(s.dir, "relay-known", safePointFile(pointID)+".json")
}

// safePointFile keeps a local id usable as a file name and refuses traversal.
func safePointFile(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	out := b.String()
	if out == "" {
		return "point"
	}
	return out
}

// LoadRelayKnown reads one point's cache. A missing file returns
// (nil, nil), which the caller treats as "never initialised"; a broken file
// returns ErrRelayKnownCorrupt so the protection gap is visible.
func (s *Store) LoadRelayKnown(pointID string) (*RelayKnown, error) {
	s.relayKnown.Lock()
	defer s.relayKnown.Unlock()
	return s.loadRelayKnown(pointID)
}

// loadRelayKnown reads without taking the lock; callers hold it.
func (s *Store) loadRelayKnown(pointID string) (*RelayKnown, error) {
	path := s.RelayKnownPath(pointID)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Size() > RelayKnownMaxBytes {
		return nil, fmt.Errorf("%w：文件超过 %d 字节", ErrRelayKnownCorrupt, RelayKnownMaxBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var known RelayKnown
	if err := json.Unmarshal(data, &known); err != nil {
		return nil, fmt.Errorf("%w：%v", ErrRelayKnownCorrupt, err)
	}
	if known.Schema != RelayKnownSchema || known.PointID != pointID || known.Resources == nil {
		return nil, fmt.Errorf("%w：字段不匹配", ErrRelayKnownCorrupt)
	}
	return &known, nil
}

// SaveRelayKnown records a verified snapshot as the newest attribution history.
//
// It never replaces what is already known: the stored cache is the union of the
// previous history and this snapshot, so a target that was withdrawn stays
// owned and cannot fall back to the original network later. The whole
// read-verify-merge-write runs under one lock per store, so concurrent saves of
// the same node cannot drop each other's history.
//
// A snapshot whose source no longer matches the stored node is refused:
// re-importing or deleting a node invalidates any session that is still running.
func (s *Store) SaveRelayKnown(pointID string, source RelaySource, resources *workeripc.ResourceSnapshot) error {
	if resources == nil {
		return nil
	}
	s.relayKnown.Lock()
	defer s.relayKnown.Unlock()

	if err := s.checkRelaySource(pointID, source); err != nil {
		return err
	}
	history := resources
	if old, err := s.loadRelayKnown(pointID); err != nil {
		// A broken cache is kept on disk as evidence, but it must not stop a
		// verified snapshot from being stored: refusing would lose even the
		// history the caller still has in memory.
		if !errors.Is(err, ErrRelayKnownCorrupt) {
			return err
		}
	} else if old != nil {
		history = attribution.Merge(old.Resources, resources)
	}
	known := RelayKnown{
		Schema:      RelayKnownSchema,
		PointID:     pointID,
		Source:      source.Label,
		ShareID:     source.ShareID,
		Fingerprint: source.Fingerprint,
		SavedAt:     time.Now().Unix(),
		Resources:   history,
	}
	data, err := json.MarshalIndent(known, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > RelayKnownMaxBytes {
		return fmt.Errorf("局域网分享的历史归属超过 %d 字节，未保存", RelayKnownMaxBytes)
	}
	dir := filepath.Join(s.dir, "relay-known")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, safePointFile(pointID)+".json"), append(data, '\n'), 0o600)
}

// checkRelaySource refuses a snapshot that does not belong to the stored node.
// The node must still exist, still be a relay, and still carry the same share id
// and certificate fingerprint the snapshot was authenticated with.
func (s *Store) checkRelaySource(pointID string, source RelaySource) error {
	s.mu.Lock()
	point := s.cfg.Find(pointID)
	var ident *model.RelayPointOptions
	if point != nil {
		ident = point.Relay
	}
	s.mu.Unlock()
	if ident == nil {
		return fmt.Errorf("%w：节点已删除或已不是局域网中继", ErrRelayKnownStaleSource)
	}
	if ident.ShareID != source.ShareID || ident.CertificateSHA256 != source.Fingerprint {
		return fmt.Errorf("%w：分享身份已变化", ErrRelayKnownStaleSource)
	}
	return nil
}

// DeleteRelayKnown removes a point's cache, which deleting the node does.
func (s *Store) DeleteRelayKnown(pointID string) error {
	s.relayKnown.Lock()
	defer s.relayKnown.Unlock()
	err := os.Remove(s.RelayKnownPath(pointID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// SetRelayHistoryInitialized flips the point's history marker and persists it.
// The marker says "a first verified snapshot was stored"; it is not a
// credential and grants nothing.
func (s *Store) SetRelayHistoryInitialized(pointID string) error {
	_, err := s.Update(func(cfg *model.Config) error {
		point := cfg.Find(pointID)
		if point == nil {
			return fmt.Errorf("接入点 %s 不存在", pointID)
		}
		if point.Relay == nil {
			return fmt.Errorf("接入点 %s 不是局域网中继节点", pointID)
		}
		point.Relay.HistoryInitialized = true
		return nil
	})
	if err != nil {
		return err
	}
	return s.Save()
}
