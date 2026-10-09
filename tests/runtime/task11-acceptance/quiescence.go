package main

import (
	"context"
	"errors"
	"strings"
	"time"
)

func operationPopulated(raw []byte) (bool, error) {
	if len(raw) == 0 || len(raw) > 4096 {
		return false, errors.New("cgroup events unavailable")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		p := strings.Fields(line)
		if len(p) != 2 || (p[0] != "populated" && p[0] != "frozen") || (p[1] != "0" && p[1] != "1") || fields[p[0]] != "" {
			return false, errors.New("ambiguous cgroup population evidence")
		}
		fields[p[0]] = p[1]
	}
	if fields["populated"] == "" {
		return false, errors.New("cgroup population missing")
	}
	return fields["populated"] == "1", nil
}
func awaitOperationEmpty(ctx context.Context, read func() ([]byte, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw, err := read()
		if err != nil {
			return err
		}
		populated, err := operationPopulated(raw)
		if err != nil {
			return err
		}
		if !populated {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
