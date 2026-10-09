package main

import "encoding/json"

// remoteState is private synthetic API state, never an application readiness marker.
// Requests own immutable remote versions; callers cannot replace their payloads.
type remoteState struct {
	Peers               map[string]peerPolicy               `json:"peers"`
	SeedSHA256          string                              `json:"seed_sha256"`
	Events              []remoteEvent                       `json:"events"`
	Batches             []intakeBatch                       `json:"batches"`
	Commands            map[string]fleetCommand             `json:"commands"`
	SubmissionUncertain bool                                `json:"submission_uncertain"`
	InventoryError      bool                                `json:"inventory_error"`
	IntakeUnavailable   bool                                `json:"intake_unavailable"`
	Schema              int                                 `json:"schema"`
	Secrets             map[string]map[string]secretVersion `json:"secrets"`
}

func (f *fixture) initializeRemote() {
	if f.remote != nil {
		return
	}
	seedBytes, _ := json.Marshal(f.config)
	seedHash := f.seedSHA256
	if seedHash == "" {
		seedHash = digestBytes(seedBytes)
	}
	f.remote = &remoteState{Schema: 1, Peers: map[string]peerPolicy{}, SeedSHA256: seedHash, Commands: map[string]fleetCommand{}, Secrets: map[string]map[string]secretVersion{}}
	if f.config.Contract != nil {
		for ip, policy := range f.config.Contract.Peers {
			f.remote.Peers[ip] = policy
		}
	}
	if f.config.Contract != nil && f.config.Contract.Fleet != nil {
		for _, command := range f.config.Contract.Fleet.Commands {
			command.Mode = "pending"
			command.UpdatedAt = command.CreatedAt
			f.remote.Commands[command.UUID] = command
		}
	}
	for name, versions := range f.config.Secrets {
		f.remote.Secrets[name] = map[string]secretVersion{}
		for version, data := range versions {
			f.remote.Secrets[name][version] = secretVersion{Data: data, State: "ENABLED"}
		}
	}
}
