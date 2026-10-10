//go:build !linux

package main

import "errors"

func (o operation) prepareNAS() error { return errors.New("actual Linux NAS assembly required") }
func (o operation) auditNAS() error   { return errors.New("actual Linux NAS mount audit required") }
