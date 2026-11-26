package contract

// SessionWatcher is a Session that reports when its tunnel ends without
// Close being called.
type SessionWatcher interface {
	Done() <-chan struct{}
	Err() error
}
