package main

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type passiveAuditResult struct {
	Schema           int    `json:"schema"`
	Kind             string `json:"kind"`
	Mode             string `json:"mode"`
	SeedSHA256       string `json:"seed_sha256"`
	Peer             string `json:"peer"`
	Role             string `json:"role"`
	Policy           string `json:"policy"`
	FromSequence     int    `json:"from_sequence"`
	ToSequence       int    `json:"to_sequence"`
	BaselineSHA256   string `json:"baseline_sha256"`
	EvidenceSHA256   string `json:"evidence_sha256"`
	Events           int    `json:"events"`
	ReadAttempts     int    `json:"read_attempts"`
	SuccessfulReads  int    `json:"successful_reads"`
	HTTPRequests     int    `json:"http_requests"`
	GRPCRequests     int    `json:"grpc_requests"`
	ControlEvents    int    `json:"control_events"`
	OtherPeerEvents  int    `json:"other_peer_events"`
	MutationAttempts int    `json:"mutation_attempts"`
}

func passiveAuditCommand() *cobra.Command {
	var seedPin, peerIP, baseline string
	var after int
	cmd := &cobra.Command{Use: "passive-audit baseline|final", Short: "Audit actual passive peer API history without asserting product state", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return withContract("installed-traffic", func(f *fixture) error {
			result, err := f.auditPassive(args[0], seedPin, peerIP, after, baseline)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		})
	}}
	cmd.Flags().StringVar(&seedPin, "seed-sha256", "", "exact reviewed installed seed file SHA256")
	cmd.Flags().StringVar(&peerIP, "peer", "", "exact seeded green peer IP")
	cmd.Flags().IntVar(&after, "after-sequence", -1, "actual caller-retained baseline sequence; final only")
	cmd.Flags().StringVar(&baseline, "baseline-sha256", "", "actual caller-retained baseline prefix hash; final only")
	return cmd
}

// This function is called only under withContract's existing private file lock
// and journal/state audit by the CLI. A prefix hash binds a caller-retained
// baseline; it is not authorization, a product phase receipt or a boot marker.
func (f *fixture) auditPassive(mode, seedPin, peerIP string, after int, baseline string) (passiveAuditResult, error) {
	out := passiveAuditResult{}
	if f.config.Contract == nil || f.config.Contract.Gate != "installed-traffic" || f.config.Contract.validate() != nil || f.remote == nil || !shaPin.MatchString(seedPin) || seedPin != f.seedSHA256 || seedPin != f.remote.SeedSHA256 || (peerIP != "10.203.11.21" && peerIP != "10.203.11.22") {
		return out, errors.New("exact installed seed and green peer required")
	}
	if mode != "baseline" && mode != "final" {
		return out, errors.New("unknown passive audit mode")
	}
	if mode == "baseline" {
		if after != -1 || baseline != "" {
			return out, errors.New("baseline does not accept a prior window")
		}
		after = len(f.remote.Events)
	} else if after < 0 || after > len(f.remote.Events) || !shaPin.MatchString(baseline) {
		return out, errors.New("invalid passive baseline cursor")
	}
	phases, err := f.passiveHistory(peerIP)
	if err != nil {
		return out, err
	}
	if phases[after] != "passive" || phases[len(phases)-1] != "passive" {
		return out, errors.New("peer is not passive at both window boundaries")
	}
	bound, err := f.passivePrefix(seedPin, peerIP, after)
	if err != nil {
		return out, err
	}
	if mode == "final" && baseline != bound {
		return out, errors.New("baseline prefix is not bound to this seed, peer and sequence")
	}
	out = passiveAuditResult{Schema: 1, Kind: "passive-peer-audit", Mode: mode, SeedSHA256: seedPin, Peer: peerIP, Role: ownedPeerRoles[peerIP], Policy: "passive", FromSequence: after, ToSequence: len(f.remote.Events), BaselineSHA256: bound}
	for i := after; i < len(f.remote.Events); i++ {
		if phases[i] != "passive" || phases[i+1] != "passive" {
			return passiveAuditResult{}, errors.New("peer policy became active in passive window")
		}
		event := f.remote.Events[i]
		if event.Protocol == "controller" {
			out.ControlEvents++
			continue
		}
		if event.PeerIP != peerIP {
			out.OtherPeerEvents++
			continue
		}
		out.Events++
		if event.Protocol == "http" {
			out.HTTPRequests++
		} else {
			out.GRPCRequests++
		}
		if !f.passiveRead(event) {
			return passiveAuditResult{}, errors.New("selected passive peer attempted remote mutation")
		}
		out.ReadAttempts++
		if event.Protocol == "http" && event.Status >= 200 && event.Status < 300 || event.Protocol == "grpc" && event.Status == 0 {
			out.SuccessfulReads++
		}
	}
	end, err := f.passivePrefix(seedPin, peerIP, len(f.remote.Events))
	if err != nil {
		return passiveAuditResult{}, err
	}
	proof, err := json.Marshal(struct {
		Result    passiveAuditResult `json:"result"`
		EndPrefix string             `json:"end_prefix_sha256"`
	}{out, end})
	if err != nil {
		return passiveAuditResult{}, err
	}
	out.EvidenceSHA256 = digestBytes(proof)
	return out, nil
}
func (f *fixture) passiveRead(event remoteEvent) bool {
	if event.Protocol == "grpc" {
		return event.Target == kmsService+"GetPublicKey"
	}
	if event.Method != "GET" {
		return false
	}
	authority, path, ok := strings.Cut(event.Target, "/")
	if !ok {
		return false
	}
	for _, route := range f.config.Routes {
		if normalizedAuthority(authority) == route.Host && "/"+path == route.Target && event.Method == route.Method && route.Mutation {
			return false
		}
	}
	return true
}
func (f *fixture) passivePrefix(seedPin, peerIP string, sequence int) (string, error) {
	// Make an explicit empty slice so a zero-event prefix is identical before
	// and after later events have allocated the underlying state slice.
	prefix := make([]remoteEvent, sequence)
	copy(prefix, f.remote.Events[:sequence])
	data, err := json.Marshal(struct {
		Schema   int           `json:"schema"`
		Kind     string        `json:"kind"`
		Seed     string        `json:"seed_sha256"`
		Peer     string        `json:"peer"`
		Role     string        `json:"role"`
		Sequence int           `json:"sequence"`
		Events   []remoteEvent `json:"events"`
	}{1, "passive-peer-prefix", seedPin, peerIP, ownedPeerRoles[peerIP], sequence, prefix})
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}

// Existing general history validation remains unchanged. This stricter reader
// additionally rejects unsupported protocols/callers/control arguments and
// reconstructs every selected-peer boundary, including no-traffic transitions.
func (f *fixture) passiveHistory(peerIP string) ([]string, error) {
	if len(f.remote.Events) > 8192 {
		return nil, errors.New("passive audit event bound exceeded")
	}
	if err := f.auditPeerHistory(false); err != nil {
		return nil, err
	}
	phase := f.config.Contract.Peers[peerIP].Phase
	phases := []string{phase}
	known := map[string]string{}
	uncertain, inventoryError, intakeUnavailable := false, false, false
	if f.config.Contract.Fleet != nil {
		for _, command := range f.config.Contract.Fleet.Commands {
			known[command.UUID] = "pending"
		}
	}
	for i, event := range f.remote.Events {
		if event.Sequence != i+1 || !shaPin.MatchString(event.BodySHA256) || event.BodyBytes < 0 || event.BodyBytes > maxBody || len(event.Target) > 4096 {
			return nil, errors.New("invalid bounded event identity")
		}
		if _, err := time.Parse(time.RFC3339Nano, event.Time); err != nil {
			return nil, errors.New("invalid recorded event time")
		}
		switch event.Protocol {
		case "controller":
			if event.Method != "SCENARIO" || event.Status != 0 || event.Phase != "active" || event.PeerIP != "" || event.PeerRole != "" {
				return nil, errors.New("unbound controller event")
			}
			switch event.Target {
			case "peer-active", "peer-passive":
				var change struct {
					Peer  string `json:"peer"`
					Phase string `json:"phase"`
				}
				if strictJSON(event.Observation, &change) != nil || event.BodyBytes != len(change.Peer) || event.BodySHA256 != digestBytes([]byte(change.Peer)) {
					return nil, errors.New("unbound peer policy arguments")
				}
				if change.Peer == peerIP {
					phase = change.Phase
				}
			case "fleet-pending", "fleet-missing", "fleet-terminal":
				matches := 0
				boundID := ""
				for id := range known {
					if event.BodyBytes == len(id) && event.BodySHA256 == digestBytes([]byte(id)) {
						matches++
						boundID = id
					}
				}
				if matches != 1 || len(event.Observation) != 0 || known[boundID] == "terminal" {
					return nil, errors.New("unbound Fleet scenario arguments")
				}
				known[boundID] = strings.TrimPrefix(event.Target, "fleet-")
			case "fleet-uncertain", "inventory-error", "inventory-ready", "intake-unavailable", "intake-ready":
				if event.BodyBytes != 0 || event.BodySHA256 != digestBytes(nil) || len(event.Observation) != 0 {
					return nil, errors.New("unexpected scenario arguments")
				}
				switch event.Target {
				case "fleet-uncertain":
					uncertain = true
				case "inventory-error":
					inventoryError = true
				case "inventory-ready":
					inventoryError = false
				case "intake-unavailable":
					intakeUnavailable = true
				case "intake-ready":
					intakeUnavailable = false
				}
			default:
				return nil, errors.New("unknown controller scenario")
			}
		case "http", "grpc":
			if ownedPeerRoles[event.PeerIP] == "" || event.PeerRole != ownedPeerRoles[event.PeerIP] {
				return nil, errors.New("unrecognized actual transport peer")
			}
			if event.Protocol == "grpc" {
				if event.Method != "POST" || (event.Target != kmsService+"GetPublicKey" && event.Target != kmsService+"AsymmetricSign") || event.Status < 0 || event.Status > 16 {
					return nil, errors.New("unsupported gRPC event")
				}
			} else {
				if (event.Method != "GET" && event.Method != "POST") || (event.Status != 0 && (event.Status < 100 || event.Status > 599)) {
					return nil, errors.New("unsupported HTTP event")
				}
				if event.Method == "POST" && (event.Status == 0 || event.Status == 200) && (event.Target == "fleet.task11.test/api/v1/fleet/commands/run" || event.Target == "fleet.task11.test/api/v1/fleet/scripts/run") {
					matches := 0
					for id, command := range f.remote.Commands {
						if command.BodySHA256 == event.BodySHA256 {
							if _, exists := known[id]; exists {
								return nil, errors.New("repeated accepted command in controller history")
							}
							known[id] = "pending"
							matches++
						}
					}
					if matches != 1 {
						return nil, errors.New("accepted Fleet command identity absent")
					}
				}
			}
		default:
			return nil, errors.New("unknown journal protocol")
		}
		phases = append(phases, phase)
	}
	if len(known) != len(f.remote.Commands) || uncertain != f.remote.SubmissionUncertain || inventoryError != f.remote.InventoryError || intakeUnavailable != f.remote.IntakeUnavailable {
		return nil, errors.New("controller state differs from journal")
	}
	for id, mode := range known {
		if f.remote.Commands[id].Mode != mode {
			return nil, errors.New("command result state differs from journal")
		}
	}
	return phases, nil
}
