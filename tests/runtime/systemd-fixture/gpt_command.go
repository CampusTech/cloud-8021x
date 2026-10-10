package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"

	"github.com/spf13/cobra"
)

// gpt-plan only reads pinned inputs and prints a reviewable plan. No image writer
// is present: approval of this command cannot implicitly create a derivative.
func gptCommand() *cobra.Command {
	var source, sourcePin, boot, bootPin string
	c := &cobra.Command{Use: "gpt-plan", Args: cobra.NoArgs, SilenceUsage: true, RunE: func(cmd *cobra.Command, _ []string) error {
		s, err := openGPTInput(source, sourcePin)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		b, err := openGPTInput(boot, bootPin)
		if err != nil {
			return err
		}
		defer func() { _ = b.Close() }()
		if err := distinctGPTInputs(s, b); err != nil {
			return err
		}
		si, err := s.Stat()
		if err != nil {
			return err
		}
		bi, err := b.Stat()
		if err != nil {
			return err
		}
		plan, err := planGPT(s, b, si.Size(), bi.Size(), rand.Reader)
		if err != nil {
			return err
		}
		if plan.SourceSHA256 != sourcePin || plan.BootSHA256 != bootPin {
			return errors.New("pinned input changed during planning")
		}
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	}}
	c.Flags().StringVar(&source, "source", "", "owned source image (read-only)")
	c.Flags().StringVar(&sourcePin, "source-sha256", "", "exact source SHA256")
	c.Flags().StringVar(&boot, "boot", "", "owned boot image (read-only)")
	c.Flags().StringVar(&bootPin, "boot-sha256", "", "exact boot SHA256")
	return c
}
