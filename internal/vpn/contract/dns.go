package contract

import (
	"context"
)

// DNSExchanger is optional; aTrust sessions retain their existing behavior.
// It only accepts internal DNS questions scoped to this EasyConnect session.
type DNSExchanger interface {
	ExchangeDNS(context.Context, []byte) ([]byte, error)
}
