package contract

// RelaySnapshotSource is the authenticated identity of the share a snapshot came
// from, captured while the session was pinned at connect time. The persistence
// hook verifies it against the stored node, so a late snapshot from a share the
// user has since re-imported cannot be written.
type RelaySnapshotSource struct {
	ShareID     string
	Fingerprint string
}
