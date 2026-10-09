//go:build !linux

package main

import (
	"context"
	"errors"
	"io"

	"github.com/sirupsen/logrus"
)

func executeStage(context.Context, string, *logrus.Logger) error {
	return errors.New("requires enrolled Linux guest; no host execution")
}
func nodeCommand(context.Context, []string, io.Reader, io.Writer) error {
	return errors.New("requires enrolled Linux guest; no host execution")
}
func seedGuest() error { return errors.New("requires enrolled Linux guest; no host execution") }

func sourcePolicy(context.Context) error { return errors.New("requires enrolled Linux source") }
func sourceRender() error                { return errors.New("requires enrolled Linux source") }

func sourceWriter(context.Context) error { return errors.New("requires enrolled Linux source") }

func requestedStage(context.Context) error {
	return errors.New("requires enrolled Linux controller service")
}
