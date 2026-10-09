package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func gateRoot(gate string) (string, error) {
	switch gate {
	case "primitive-contract":
		return "/var/lib/cloud8021x-task11/control/primitive-api", nil
	case "installed-traffic":
		return fixedCloudRoot, nil
	default:
		return "", errors.New("unknown fixed verification gate")
	}
}
func ownedGuest() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("owned root Linux guest required")
	}
	marker, err := os.ReadFile("/etc/cloud8021x-task11-fixture")
	if err != nil || string(marker) != "synthetic-only-v1\n" {
		return errors.New("owned fixture marker missing")
	}
	return nil
}
func withContract(gate string, operation func(*fixture) error) error {
	if err := ownedGuest(); err != nil {
		return err
	}
	root, err := gateRoot(gate)
	if err != nil {
		return err
	}
	// No configurable path or remote HTTP control endpoint. The controller runs
	// this fixed guest-root command and separately pins the verifier executable.
	journal, err := privateFile(filepath.Join(root, "journal.jsonl"), unix.O_APPEND|unix.O_WRONLY)
	if err != nil {
		return err
	}
	defer func() { _ = journal.Close() }()
	f, err := loadFixture(root, "active", journal)
	if err != nil {
		return err
	}
	if f.config.Contract == nil || f.config.Contract.Gate != gate {
		return errors.New("fixture gate differs")
	}
	release, err := f.openRemote()
	if err != nil {
		return err
	}
	defer release()
	return operation(f)
}
func verifyCommand() *cobra.Command {
	var gate, application, expectedHash string
	command := &cobra.Command{Use: "verify", Short: "Verify actual private remote evidence against a separately pinned projection", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if !shaPin.MatchString(application) || !shaPin.MatchString(expectedHash) {
			return errors.New("exact application and projection pins required")
		}
		return withContract(gate, func(f *fixture) error {
			data, err := privateRead(filepath.Join(f.stateRoot, "expected.json"))
			if err != nil {
				return err
			}
			if digestBytes(data) != expectedHash {
				return errors.New("expected projection pin differs")
			}
			expected, err := parsedProjection(data)
			if err != nil {
				return err
			}
			result, err := f.verifyEvidence(expected, application)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		})
	}}
	command.Flags().StringVar(&gate, "gate", "", "primitive-contract or installed-traffic; distinct fixed evidence roots")
	command.Flags().StringVar(&application, "application-sha256", "", "reviewed application pin")
	command.Flags().StringVar(&expectedHash, "expected-sha256", "", "controller pin of actual projection bytes")
	return command
}
func scenarioCommand() *cobra.Command {
	var gate, uuid, peerIP string
	command := &cobra.Command{Use: "scenario NAME", Short: "Advance one explicit synthetic remote failure/result scenario", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withContract(gate, func(f *fixture) error {
			return f.runScenario(args[0], uuid, peerIP)
		})
	}}
	command.Flags().StringVar(&gate, "gate", "installed-traffic", "fixed private remote state root")
	command.Flags().StringVar(&peerIP, "peer", "", "exact seeded green peer for mutation policy changes")
	command.Flags().StringVar(&uuid, "command", "", "exact existing command UUID for a Fleet result transition")
	return command
}

func (f *fixture) runScenario(name, uuid, peerIP string) error {
	f.initializeRemote()
	f.callerIP = ""
	f.callerRole = ""
	if name == "peer-active" || name == "peer-passive" {
		if uuid != "" {
			return errors.New("peer policy does not accept command UUID")
		}
		if err := f.changePeerPolicy(peerIP, strings.TrimPrefix(name, "peer-")); err != nil {
			return err
		}
	} else {
		if peerIP != "" {
			return errors.New("scenario does not accept peer")
		}
		if err := f.advanceScenario(name, uuid); err != nil {
			return err
		}
	}

	f.observation = nil
	if peerIP != "" {
		f.observation, _ = json.Marshal(struct {
			Peer  string `json:"peer"`
			Phase string `json:"phase"`
		}{peerIP, strings.TrimPrefix(name, "peer-")})
	}
	return f.recordRemote("controller", "SCENARIO", name, []byte(uuid+peerIP), 0)
}
