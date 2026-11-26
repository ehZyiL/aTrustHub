package contract

// SessionUpdate is one immutable snapshot a session publishes after it is
// online. Sequence is strictly increasing per session generation.
type SessionUpdate struct {
	Sequence uint64
	Info     SessionInfo
}

// SessionUpdater is implemented by sessions that can report resource changes
// without reconnecting. Sessions without it keep their original behaviour.
type SessionUpdater interface {
	Updates() <-chan SessionUpdate
}
