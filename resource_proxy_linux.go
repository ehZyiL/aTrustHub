package main

func suspendProxyForResourceTUN(string, string, func(string)) (func() error, error) {
	return nil, nil
}

func recoverResourceProxy(string) error { return nil }
func systemProxyOwned(string) bool      { return false }

// systemProxyForeign 在本平台没有可读的系统代理设置（Linux 不支持这一档）。
func systemProxyForeign(string) bool { return false }
