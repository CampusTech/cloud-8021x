package main

import "testing"

func observedPinnedBudget() budget {
	return budget{SourceBytes: 991618472, LowerBytes: 1792 * MiB, StagingBytes: 300 * MiB, PrivateBytes: 64 * MiB, Inodes: 34102, FreeBytes: 14167519232, FreeInodes: 1003668}
}
func TestBudgetAvailableUsesCurrentCapacityWithoutMutatingPinnedBudget(t *testing.T) {
	b := observedPinnedBudget()
	before := b
	if e := b.validate(); e != nil {
		t.Fatal(e)
	}
	if e := b.available(14167318528, 1003629); e != nil {
		t.Fatal("sufficient observed current capacity refused after owned publications", e)
	}
	if b != before {
		t.Fatal("pinned budget rewritten")
	}
}
func TestBudgetAvailablePreservesByteAndInodeReserveBoundaries(t *testing.T) {
	b := observedPinnedBudget()
	bytes, inodes := 1792*MiB+backingBytes+GiB, b.Inodes+100000
	for _, tc := range []struct {
		name          string
		bytes, inodes int64
		allowed       bool
	}{
		{"exact-reviewed-reserves", bytes, inodes, true},
		{"one-byte-short", bytes - 1, inodes, false},
		{"one-inode-short", bytes, inodes - 1, false},
		{"negative-bytes", -1, inodes, false},
		{"negative-inodes", bytes, -1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if e := b.available(tc.bytes, tc.inodes); (e == nil) != tc.allowed {
				t.Fatal("current capacity reserve boundary changed", e)
			}
		})
	}
}
func TestBudgetAvailableFirstRefusesInvalidProtectedBudget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*budget)
	}{
		{"source-cap", func(b *budget) { b.SourceBytes = 1536*MiB + 1 }},
		{"lower-cap", func(b *budget) { b.LowerBytes = 1792*MiB + 1 }},
		{"lower-below-source", func(b *budget) { b.LowerBytes = b.SourceBytes - 1 }},
		{"staging-cap", func(b *budget) { b.StagingBytes = 512*MiB + 1 }},
		{"private-cap", func(b *budget) { b.PrivateBytes = 128*MiB + 1 }},
		{"inode-cap", func(b *budget) { b.Inodes = 200001 }},
		{"invalid-original-byte-admission", func(b *budget) { b.FreeBytes = 1792*MiB + backingBytes + GiB - 1 }},
		{"invalid-original-inode-admission", func(b *budget) { b.FreeInodes = b.Inodes + 100000 - 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := observedPinnedBudget()
			tc.mutate(&b)
			if e := b.available(16*GiB, 2000000); e == nil {
				t.Fatal("current measurement laundered invalid protected budget")
			}
		})
	}
}
