package main

import "testing"

func TestEitherActivationOrderAndRebootRetainExactOwnedPair(t *testing.T) {
	pair := []string{"/dev/loop8", "/dev/loop9"}
	p, s := backingIdentity{10, 100}, backingIdentity{20, 200}
	owned := map[backingIdentity]string{p: "green-primary", s: "green-secondary"}
	for _, first := range []backingIdentity{p, s} {
		second := p
		if first == p {
			second = s
		}
		for _, n := range []int{0, 1, 2} {
			actual := map[string]loopObservation{pair[0]: {}, pair[1]: {}}
			free := []string{pair[0], pair[1], "/dev/loop10"}
			if n >= 1 {
				actual[pair[0]] = loopObservation{true, first}
				free = free[1:]
			}
			if n == 2 {
				actual[pair[1]] = loopObservation{true, second}
				free = free[1:]
			}
			if e := validateLoopAllocation(pair, free, actual, owned); e != nil {
				t.Fatal(e)
			}
			if n < 2 && validateLoopAllocation(pair, append([]string{"/dev/loop0"}, free...), actual, owned) == nil {
				t.Fatal("invisible first-free loop accepted")
			}
		}
	}
	actual := map[string]loopObservation{pair[0]: {true, backingIdentity{99, 99}}, pair[1]: {}}
	if validateLoopAllocation(pair, []string{pair[1]}, actual, owned) == nil {
		t.Fatal("foreign loop backing accepted")
	}
}

func TestCollectorAttachedOutsideExposedPairIsRefused(t *testing.T) {
	p := backingIdentity{10, 100}
	observed := map[string]loopObservation{"/dev/loop8": {}, "/dev/loop9": {}, "/dev/loop10": {true, p}}
	if validateLoopAllocation([]string{"/dev/loop8", "/dev/loop9"}, []string{"/dev/loop8", "/dev/loop9"}, observed, map[backingIdentity]string{p: "green-primary"}) == nil {
		t.Fatal("owned image attached outside the approved device pair was accepted")
	}
}
