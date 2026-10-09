// task11-passive-audit is a development-only read-only enrolled-node observer.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-passive-audit/contract"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func command() *cobra.Command {
	root := &cobra.Command{Use: "task11-passive-audit", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(&cobra.Command{Use: "observe", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		raw, e := io.ReadAll(io.LimitReader(cmd.InOrStdin(), contract.MaxRequestBytes+1))
		if e != nil || len(raw) > contract.MaxRequestBytes {
			return errors.New("request exceeds fixed bound")
		}
		var r contract.Request
		if domain.DecodeJSONStrict(raw, &r) != nil || contract.ValidateRequest(r) != nil {
			return errors.New("strict enrolled request required")
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 45*time.Second)
		defer cancel()
		result, e := observe(ctx, r, digest(raw))
		clear(raw)
		if e != nil {
			return e
		}
		encoded, e := json.Marshal(result)
		if e != nil || len(encoded) > contract.MaxResultBytes {
			return errors.New("bounded observation unavailable")
		}
		_, e = cmd.OutOrStdout().Write(append(encoded, '\n'))
		return e
	}})
	return root
}
func main() {
	if e := command().Execute(); e != nil {
		logrus.WithField("component", "task11-passive-audit").Error("passive observation refused")
		os.Exit(1)
	}
}
