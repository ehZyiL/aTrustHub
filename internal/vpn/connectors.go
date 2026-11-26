package vpn

import (
	"context"
	"fmt"

	"github.com/ehzyil/connect-hub/internal/model"
)

// Registration is a single connector supplied by application assembly. It has
// no init hook or global registry, so construction cannot start optional work.
type Registration struct {
	Protocol string
	Connect  Connector
}

// UnavailableProtocolError distinguishes unavailable features from login errors.
type UnavailableProtocolError struct{ Protocol string }

func (e *UnavailableProtocolError) Error() string {
	return fmt.Sprintf("连接功能不可用或未安装：%q", e.Protocol)
}

// Dispatch snapshots its registrations. Invalid or duplicated entries fail
// closed; no supplied connector can silently replace another one.
func Dispatch(entries ...Registration) Connector {
	registered := make(map[string]Connector, len(entries))
	var setupErr error
	for _, entry := range entries {
		if entry.Protocol == "" || entry.Connect == nil || registered[entry.Protocol] != nil {
			setupErr = fmt.Errorf("无效或重复的连接器注册：%q", entry.Protocol)
			break
		}
		registered[entry.Protocol] = entry.Connect
	}
	return func(ctx context.Context, point model.AccessPoint, creds Credentials) (Session, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if setupErr != nil {
			return nil, setupErr
		}
		protocol := point.Protocol
		if protocol == "" {
			protocol = model.ProtocolATrust
		}
		connect := registered[protocol]
		if connect == nil {
			return nil, &UnavailableProtocolError{Protocol: protocol}
		}
		return connect(ctx, point, creds)
	}
}
