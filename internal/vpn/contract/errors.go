package contract

import (
	"errors"
)

var ErrStrictVPNUnavailable = errors.New("当前核心不支持严格 VPN 拨号，请更新配套核心")
