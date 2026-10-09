package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOperationQuiescenceRequiresActualTerminalKernelZero(t *testing.T) {
	t.Run("still-populated", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		if awaitOperationEmpty(ctx, func() ([]byte, error) { return []byte("populated 1\nfrozen 0\n"), nil }) == nil {
			t.Fatal("reported quiescence while owned descendants remain")
		}
	})
	for _, data := range []string{"", "frozen 0\n", "populated 0\npopulated 1\n", "populated 2\n", "populated nope\n"} {
		t.Run(data, func(t *testing.T) {
			if awaitOperationEmpty(context.Background(), func() ([]byte, error) { return []byte(data), nil }) == nil {
				t.Fatal("unknown cgroup evidence became a successful zero")
			}
		})
	}
	t.Run("read-failure", func(t *testing.T) {
		if awaitOperationEmpty(context.Background(), func() ([]byte, error) { return nil, errors.New("unavailable") }) == nil {
			t.Fatal("read failure became quiescence")
		}
	})
	t.Run("population-drains", func(t *testing.T) {
		calls := 0
		err := awaitOperationEmpty(context.Background(), func() ([]byte, error) {
			calls++
			if calls == 1 {
				return []byte("populated 1\nfrozen 0\n"), nil
			}
			return []byte("populated 0\nfrozen 0\n"), nil
		})
		if err != nil || calls != 2 {
			t.Fatalf("did not await independently observed zero: calls=%d err=%v", calls, err)
		}
	})
}

func TestCancelledQuiescenceDoesNotClaimAnUnreadZero(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reads := 0
	if err := awaitOperationEmpty(ctx, func() ([]byte, error) { reads++; return []byte("populated 0\n"), nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled proof: %v", err)
	}
	if reads != 0 {
		t.Fatal("expired proof attempted a new observation")
	}
}
