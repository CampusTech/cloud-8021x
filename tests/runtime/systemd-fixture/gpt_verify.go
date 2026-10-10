package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

type pinnedGPTImage struct {
	path, pin string
	size      int64
}

// Verification has no write mode and opens every image O_RDONLY. CLI pins are
// independent of the plan file, so replacing both a candidate and its local hash
// cannot enlarge the approved byte changes.
func gptVerifyCommand() *cobra.Command {
	var source, boot, derivative pinnedGPTImage
	var planPath, planPin string
	c := &cobra.Command{Use: "gpt-verify", Args: cobra.NoArgs, SilenceUsage: true, RunE: func(cmd *cobra.Command, _ []string) error {
		if derivative.size != source.size {
			return errors.New("source/derivative size pins differ")
		}
		var files []*os.File
		defer func() {
			for _, f := range files {
				_ = f.Close()
			}
		}()
		for _, input := range []pinnedGPTImage{source, boot, derivative} {
			if input.size < 68*512 || input.size > 8000000000 {
				return errors.New("bounded exact image size pin required")
			}
			f, err := openGPTInput(input.path, input.pin)
			if err != nil {
				return err
			}
			files = append(files, f)
			info, err := f.Stat()
			if err != nil {
				return err
			}
			if info.Size() != input.size {
				return errors.New("image size pin mismatch")
			}
		}
		planFile, err := openGPTPinned(planPath, planPin, 1, 65536)
		if err != nil {
			return err
		}
		files = append(files, planFile)
		for i := range files {
			for j := 0; j < i; j++ {
				if err := distinctGPTInputs(files[i], files[j]); err != nil {
					return err
				}
			}
		}
		decoder := json.NewDecoder(io.NewSectionReader(planFile, 0, 65536))
		decoder.DisallowUnknownFields()
		var p gptPlan
		if err := decoder.Decode(&p); err != nil {
			return err
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return errors.New("extra content in pinned plan")
		}
		if p.SourceSHA256 != source.pin || p.BootSHA256 != boot.pin || p.ResultSHA256 != derivative.pin {
			return errors.New("plan does not match independent image pins")
		}
		if err := verifyGPT(files[0], files[2], files[1], source.size, boot.size, p); err != nil {
			return fmt.Errorf("GPT full-stream verification: %w", err)
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
			Verified         bool       `json:"verified"`
			PlanSHA256       string     `json:"plan_sha256"`
			SourceSHA256     string     `json:"source_sha256"`
			BootSHA256       string     `json:"boot_sha256"`
			DerivativeSHA256 string     `json:"derivative_sha256"`
			UnchangedSHA256  string     `json:"unchanged_ranges_sha256"`
			SourceSize       int64      `json:"source_size"`
			BootSize         int64      `json:"boot_size"`
			DerivativeSize   int64      `json:"derivative_size"`
			Patches          []gptPatch `json:"verified_exact_fields"`
		}{true, planPin, source.pin, boot.pin, derivative.pin, p.UnchangedSHA256, source.size, boot.size, derivative.size, p.Patches})
	}}
	for _, binding := range []struct {
		name  string
		image *pinnedGPTImage
	}{{"source", &source}, {"boot", &boot}, {"derivative", &derivative}} {
		c.Flags().StringVar(&binding.image.path, binding.name, "", "owned input image (read-only)")
		c.Flags().StringVar(&binding.image.pin, binding.name+"-sha256", "", "independently pinned SHA256")
		c.Flags().Int64Var(&binding.image.size, binding.name+"-size", 0, "independently pinned exact byte length")
	}
	c.Flags().StringVar(&planPath, "plan", "", "owned bounded exact plan JSON (read-only)")
	c.Flags().StringVar(&planPin, "plan-sha256", "", "independently approved plan SHA256")
	return c
}
