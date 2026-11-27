package desktop

func suspendProxyForResourceTUN(string, string, func(string)) (func() error, error) {
	return nil, nil
}

func recoverResourceProxy(string) error { return nil }
func systemProxyOwned(string) bool      { return false }

// systemProxyForeign 在本平台没有可读的系统代理设置（Linux 不支持这一档）。
func systemProxyForeign(string) bool { return false }

// systemProxyState 只在 Windows 上能读出真实值；其它平台的侦察/所有权判断都不适用。
func systemProxyState(string) string { return "本平台不支持系统代理" }
