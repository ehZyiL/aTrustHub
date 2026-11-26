package relay

import (
	"strconv"

	contract "github.com/ehzyil/connect-hub/internal/relay/contract"
)

const (
	shareIDLen    = 16
	shareTokenLen = 32
)

func itoa(n int) string { return strconv.Itoa(n) }

const ShareScheme = contract.ShareScheme

const ShareAuthority = contract.ShareAuthority

const SharePath = contract.SharePath

const ShareVersion = contract.ShareVersion

const MaxShareCodeBytes = contract.MaxShareCodeBytes

const MaxShareCodeJSON = contract.MaxShareCodeJSON

const MaxShareNameRunes = contract.MaxShareNameRunes

type ShareCode = contract.ShareCode

var ErrNotShareCode = contract.ErrNotShareCode

func ParseShareCode(text string) (ShareCode, error) { return contract.ParseShareCode(text) }
