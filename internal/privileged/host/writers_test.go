package host

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLegacyFenceQuiescenceRejectsUnknownAndActiveWriter(t *testing.T) {
	for _, output := range []string{"", "ActiveState=active\nSubState=running\nMainPID=3\n", "ActiveState=inactive\nSubState=dead\nMainPID=3\n"} {
		err := writerUnitsQuiescent(context.Background(), func(context.Context, string, ...string) ([]byte, error) { return []byte(output), nil }, legacyWriterUnits)
		if err == nil {
			t.Fatal("accepted unknown or active writer")
		}
	}
	if err := writerUnitsQuiescent(context.Background(), func(_ context.Context, path string, args ...string) ([]byte, error) {
		if path != "/usr/bin/systemctl" || !strings.HasSuffix(args[1], ".service") && !strings.HasSuffix(args[1], ".timer") {
			return nil, errors.New("unfixed probe")
		}
		return []byte("ActiveState=inactive\nSubState=dead\nMainPID=0\n"), nil
	}, legacyWriterUnits); err != nil {
		t.Fatal(err)
	}
}
