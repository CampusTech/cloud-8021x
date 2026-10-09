//go:build !linux

package main

import "context"

func nasDescriptorCall(context.Context, enrollment, string, string, []byte) ([]byte, error) {
	return nil, errNASTransport
}
func nasDescriptorEntry(context.Context, []string) error { return errNASTransport }
