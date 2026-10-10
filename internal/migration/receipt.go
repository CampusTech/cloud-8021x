package migration

import (
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"time"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ReceiptTime accepts the original numeric/ISO representation; callers retain
// that raw representation for export even when PostgreSQL rounds to microseconds.
func ReceiptTime(raw []byte) (time.Time, error) {
	text := strings.TrimSpace(string(raw))
	if strings.HasPrefix(text, "\"") {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return time.Time{}, errors.New("invalid receipt")
		}
		if t, e := time.Parse(time.RFC3339Nano, s); e == nil {
			return t, nil
		}
		text = s
	}

	if len(text) > 128 || !regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]{1,3})?$`).MatchString(text) {
		return time.Time{}, errors.New("invalid receipt")
	}
	value, ok := new(big.Rat).SetString(text)
	if !ok || value.Cmp(new(big.Rat).SetInt64(-62135596800)) < 0 || value.Cmp(new(big.Rat).SetInt64(253402300799)) > 0 {
		return time.Time{}, errors.New("invalid receipt")
	}
	whole := new(big.Int).Quo(value.Num(), value.Denom())
	remainder := new(big.Int).Rem(value.Num(), value.Denom())
	nanos := new(big.Int).Quo(new(big.Int).Mul(remainder, big.NewInt(1e9)), value.Denom())
	return time.Unix(whole.Int64(), nanos.Int64()).UTC(), nil
}
