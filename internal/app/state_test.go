package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

type fakeTransition struct {
	records, checks int
	required        error
	node, hash      string
}

func (f *fakeTransition) RecordWriterFence(_ context.Context, id, node, hash, receipt string) error {
	f.records++
	f.node = node
	f.hash = hash
	return nil
}
func (f *fakeTransition) RequireNodeWriterFences(_ context.Context, id, node, hash string) error {
	f.checks++
	return f.required
}
func TestIncomingFenceOnlyNeverRequiresCompletedCacheOrBothNodes(t *testing.T) {
	cfg := config.Config{StateTransition: strings.Repeat("a", 64), InstanceID: "radius-primary"}
	var output bytes.Buffer
	store := &fakeTransition{required: errors.New("peer not prepared")}
	gates, fences := 0, 0
	gate := func(ctx context.Context, _ string, fn func(context.Context) error) error { gates++; return fn(ctx) }
	fence := func(_ context.Context, id, node, hash string) (string, error) {
		fences++
		return strings.Repeat("b", 64), nil
	}
	err := bootstrapTransition(context.Background(), cfg, RunOptions{Incoming: true, FenceOnly: true, Output: &output}, store, gate, fence)
	if err != nil || gates != 1 || fences != 1 || store.records != 1 || store.checks != 0 || !strings.Contains(output.String(), "prepared") || strings.Contains(output.String(), "installed") {
		t.Fatalf("preparation result %v %s %+v", err, output.String(), store)
	}
	output.Reset()
	err = bootstrapTransition(context.Background(), cfg, RunOptions{}, store, gate, fence)
	if err == nil || gates != 1 || fences != 1 || store.checks != 1 || output.Len() != 0 {
		t.Fatal("full bootstrap bypassed both fences", err)
	}
	if err := bootstrapTransition(context.Background(), cfg, RunOptions{FenceOnly: true}, store, gate, fence); err == nil {
		t.Fatal("unbound fence-only selector")
	}
}
func TestFenceOnlyOutputWaitsForDurableGateCompletion(t *testing.T) {
	cfg := config.Config{StateTransition: strings.Repeat("a", 64), InstanceID: "radius-primary"}
	var out bytes.Buffer
	gate := func(ctx context.Context, _ string, fn func(context.Context) error) error {
		if err := fn(ctx); err != nil {
			return err
		}
		return errors.New("uncertain completion")
	}
	err := bootstrapTransition(context.Background(), cfg, RunOptions{Incoming: true, FenceOnly: true, Output: &out}, &fakeTransition{}, gate, func(context.Context, string, string, string) (string, error) { return strings.Repeat("b", 64), nil })
	if err == nil || out.Len() != 0 {
		t.Fatal("reported uncertain preparation")
	}
}
