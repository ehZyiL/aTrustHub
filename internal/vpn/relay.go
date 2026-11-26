package vpn

import (
	"errors"

	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	session "github.com/ehzyil/connect-hub/internal/vpn/contract"
)

// RelayReconnectable reports whether err allows the Manager's bounded reconnect
// policy to try again. Terminal credential and protocol failures do not.
func RelayReconnectable(err error) bool {
	var re *relay.Error
	if errors.As(err, &re) {
		return !re.Code.Terminal()
	}
	return true
}

type SessionUpdate = session.SessionUpdate

type SessionUpdater = session.SessionUpdater

type RelaySnapshotSource = relay.RelaySnapshotSource
