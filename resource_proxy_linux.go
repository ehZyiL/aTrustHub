package main

func suspendProxyForResourceTUN(string, string, func(string)) (func() error, error) {
	return nil, nil
}

func recoverResourceProxy(string, string) error { return nil }
func systemProxyOwned(string) bool              { return false }
