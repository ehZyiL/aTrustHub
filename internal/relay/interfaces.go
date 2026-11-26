package relay

import (
	contract "github.com/ehzyil/connect-hub/internal/relay/contract"
)

var ErrPointMissing = contract.ErrPointMissing

var ErrPointNotReady = contract.ErrPointNotReady

var ErrPointUnsupported = contract.ErrPointUnsupported

var ErrPointTunOwned = contract.ErrPointTunOwned

var ErrPointIsRelay = contract.ErrPointIsRelay

type Source = contract.Source

type Sink = contract.Sink
