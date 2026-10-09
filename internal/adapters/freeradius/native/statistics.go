package native

import (
	"context"
	"encoding/binary"
	"errors"
)

// Names and integer attributes are fixed by the shipped FreeRADIUS dictionary.
var statisticNames = map[byte]string{128: "total_access_requests", 131: "total_access_challenges", 133: "total_auth_duplicate_requests", 134: "total_auth_malformed_requests", 135: "total_auth_invalid_requests", 136: "total_auth_dropped_requests", 148: "total_acct_requests", 149: "total_acct_responses", 162: "queue_len_internal", 164: "queue_len_auth", 165: "queue_len_acct", 176: "start_time", 181: "queue_pps_in", 182: "queue_pps_out"}

func ObserveStatistics(ctx context.Context, address string, secret []byte) (map[string]uint32, error) {
	raw, err := queryStatus(ctx, address, secret, true)
	if err != nil {
		return nil, err
	}
	result := map[string]uint32{}
	for i := 20; i < len(raw); i += int(raw[i+1]) {
		n := int(raw[i+1])
		if raw[i] != 26 {
			continue
		}
		if n < 8 {
			return nil, errors.New("native statistics vendor attribute malformed")
		}
		if binary.BigEndian.Uint32(raw[i+2:i+6]) != 11344 {
			continue
		}
		for j := i + 6; j < i+n; {
			if j+2 > i+n || raw[j+1] < 2 || j+int(raw[j+1]) > i+n {
				return nil, errors.New("native statistics field malformed")
			}
			if name, ok := statisticNames[raw[j]]; ok {
				if raw[j+1] != 6 {
					return nil, errors.New("native statistics integer malformed")
				}
				if _, exists := result[name]; exists {
					return nil, errors.New("native statistics duplicated")
				}
				result[name] = binary.BigEndian.Uint32(raw[j+2 : j+6])
			}
			j += int(raw[j+1])
		}
	}
	return result, nil
}
