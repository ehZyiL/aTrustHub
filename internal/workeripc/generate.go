package workeripc

// The worker protocol lives in two checkouts: the worker's
// (zju-connect/internal/desktop/protocol.go) and this one. They must be identical
// apart from the package clause, and they are kept that way by generation rather
// than by hand:
//
//	go generate ./internal/workeripc        # copy the worker's file here
//	go run ./internal/workeripc/cmd/protogen -check -src ... -out ...   # gate
//
// The directive lives in this file on purpose: protocol.go has to stay
// byte-identical on both sides, so it cannot carry a line of its own.
//
//go:generate go run ./cmd/protogen -src ../../../zju-connect/internal/desktop/protocol.go -out protocol.go
