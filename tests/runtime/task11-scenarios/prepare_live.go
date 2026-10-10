package main

import (
	"encoding/json"
	"errors"
	"io"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func loadProducerInputs() (producerInputs, error) {
	in := producerInputs{Files: map[string][]byte{}, Configs: map[string][]byte{}}
	for _, path := range []string{outerControl, outerControl + "/original-seed"} {
		fd, e := protectedDirectoryAt(path, 0)
		if e != nil {
			return in, e
		}
		_ = unix.Close(fd)
	}
	for path, dst := range map[string]*[]byte{outerControl + "/original-seed/assembly-input.json": &in.Input, outerControl + "/original-seed/original-manifest.json": &in.Manifest, outerControl + "/platform-inventory.json": &in.Platform, outerControl + "/platform-plan.json": &in.PlatformPlan, outerControl + "/enrollment.json": &in.Enrollment} {
		raw, e := producerRead(path, 0, 64<<10, 0600)
		if e != nil {
			return in, e
		}
		*dst = raw
	}
	paths := map[string]bool{}
	for _, name := range producerOriginalNames {
		paths[name] = true
	}
	for _, name := range producerMaterialPaths {
		paths[name] = true
	}
	paths["original-manifest.json"] = true
	budget := 48 << 20
	for name := range paths {
		raw, e := producerRead(outerControl+"/original-seed/"+name, 0, 32<<20, 0600)
		if e != nil {
			return in, e
		}
		budget -= len(raw)
		if budget < 0 {
			clear(raw)
			return in, errors.New("bounded original input budget exceeded")
		}
		in.Files[name] = raw
	}
	for _, node := range []string{"blue-primary", "blue-secondary", "green-primary", "green-secondary"} {
		raw, e := producerRead("/var/lib/cloud8021x-task11/roots/task11-"+node+"/var/cache/cloud-8021x/artifacts/config.yaml", 0, 1<<20, 0600)
		if e != nil {
			return in, e
		}
		in.Configs[node] = raw
	}
	return in, nil
}
func clearProducerInputs(in producerInputs) {
	for _, raw := range in.Files {
		clear(raw)
	}
	for _, raw := range in.Configs {
		clear(raw)
	}
	clear(in.Input)
	clear(in.Manifest)
	clear(in.Platform)
	clear(in.PlatformPlan)
	clear(in.Enrollment)
}
func runPrepare(dry bool) ([]byte, error) {
	if e := syntheticNASMarker(); e != nil {
		return nil, e
	}
	in, e := loadProducerInputs()
	defer clearProducerInputs(in)
	if e != nil {
		return nil, e
	}
	bundle, e := prepareNASBundle(in)
	defer func() {
		for _, raw := range bundle.Materials {
			clear(raw)
		}
		for _, raw := range bundle.Plans {
			clear(raw)
		}
	}()
	if e != nil {
		return nil, e
	}
	v, e := validateProducerInputs(in)
	if e != nil {
		return nil, e
	}
	self := v.Platform.Helpers["task11-scenarios"].SHA256
	if e = pinOuterExecutable(self); e != nil {
		return nil, e
	}
	app, e := producerBinarySHA(outerControl + "/public/cloud-8021x")
	if e != nil || app != v.Enrollment.ApplicationSHA256 {
		return nil, errors.New("actual protected application differs")
	}
	fresh, e := loadProducerInputs()
	defer clearProducerInputs(fresh)
	if e != nil || !reflect.DeepEqual(in, fresh) {
		return nil, errors.New("protected producer inputs changed before publication")
	}
	projection := struct {
		Schema           int               `json:"schema"`
		InputSHA256      string            `json:"input_sha256"`
		PlatformSHA256   string            `json:"platform_sha256"`
		EnrollmentSHA256 string            `json:"enrollment_sha256"`
		ScenarioSHA256   string            `json:"scenario_sha256"`
		Materials        int               `json:"materials"`
		PlanSHA256       map[string]string `json:"plan_sha256"`
		DryRun           bool              `json:"dry_run"`
	}{1, digestBytes(in.Input), digestBytes(in.Platform), digestBytes(in.Enrollment), self, 13, map[string]string{}, dry}
	for name, raw := range bundle.Plans {
		projection.PlanSHA256[name] = digestBytes(raw)
	}
	raw, e := json.Marshal(projection)
	if e != nil {
		return nil, e
	}
	if !dry {
		if e = publishNASDirectories(outerControl, producerNASBacking, 0, bundle, raw); e != nil {
			return nil, e
		}
	}
	return raw, nil
}
func prepareCommand(out io.Writer) *cobra.Command {
	var dry, debug bool
	command := &cobra.Command{Use: "prepare", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if debug {
			logger := logrus.New()
			logger.SetLevel(logrus.DebugLevel)
			logger.WithFields(logrus.Fields{"action": "prepare", "dry_run": dry}).Debug("fixed private NAS producer")
		}
		raw, e := runPrepare(dry)
		if e != nil {
			return e
		}
		if _, e = out.Write(append(raw, '\n')); e != nil {
			return errors.New("bounded producer coordinates write failed")
		}
		return nil
	}}
	command.Flags().BoolVar(&dry, "dry-run", false, "Validate actual protected inputs without publication")
	command.Flags().BoolVar(&debug, "debug", false, "Keep errors and public coordinates sanitized")
	return command
}
