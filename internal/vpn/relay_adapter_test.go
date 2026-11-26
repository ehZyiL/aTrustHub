package vpn

import "github.com/ehzyil/connect-hub/internal/relay/adapter"

// Existing Manager integration fixtures exercise the extracted production
// connector through its public entry, without importing it into the core.
type RelayConnectorOptions = adapter.Options

func NewRelayConnector(options RelayConnectorOptions) Connector {
	return adapter.NewConnector(options)
}
