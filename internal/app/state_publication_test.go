package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type publicationFake struct {
	calls []string
	fail  string
}

func (s *publicationFake) ImportLegacyBundle(context.Context, string, []byte) (bool, error) {
	s.calls = append(s.calls, "import")
	return true, s.err("import")
}
func (s *publicationFake) ConfirmLegacyPublication(context.Context, string, string, string) error {
	s.calls = append(s.calls, "confirm")
	return s.err("confirm")
}
func (s *publicationFake) EnableIfPublished(context.Context, string) (bool, error) {
	s.calls = append(s.calls, "enable")
	return true, s.err("enable")
}
func (s *publicationFake) err(at string) error {
	if s.fail == at {
		return errors.New("lost acknowledgement")
	}
	return nil
}
func TestPublicationNeverEnablesAfterUnknownCommitOrLocalFailure(t *testing.T) {
	for _, failure := range []string{"import", "publish", "confirm", ""} {
		t.Run(failure, func(t *testing.T) {
			s := &publicationFake{fail: failure}
			_, e := publishLegacyState(context.Background(), s, "transition", "radius-primary", []byte("original"), false, func() error { s.calls = append(s.calls, "publish"); return s.err("publish") })
			expected := []string{"import", "publish", "confirm", "enable"}
			switch failure {
			case "import":
				expected = expected[:1]
			case "publish":
				expected = expected[:2]
			case "confirm":
				expected = expected[:3]
			}
			if !reflect.DeepEqual(s.calls, expected) || (e != nil) != (failure != "") {
				t.Fatalf("calls=%v err=%v", s.calls, e)
			}
		})
	}
}
