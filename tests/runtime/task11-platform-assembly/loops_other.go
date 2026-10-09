//go:build !linux

package main

import "errors"

func observeLoop(string) (loopObservation, error) {
	return loopObservation{}, errors.New("actual Linux loop inventory required")
}
