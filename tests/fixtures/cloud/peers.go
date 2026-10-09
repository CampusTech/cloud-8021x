package main

import (
	"errors"
	"net"
	"strings"
)

type peerPolicy struct {
	Role  string `json:"role"`
	Phase string `json:"phase"`
}

var ownedPeerRoles = map[string]string{"10.203.11.31": "original-primary", "10.203.11.32": "original-secondary", "10.203.11.21": "green-primary", "10.203.11.22": "green-secondary"}

func (f *fixture) observedPeer(address string) error {
	f.callerIP = ""
	f.callerRole = ""
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			f.callerIP = ip.String()
		}
	}
	if f.config.Contract == nil || len(f.config.Contract.Peers) == 0 {
		return nil
	}
	policy, ok := f.remote.Peers[f.callerIP]
	if !ok || policy.Role != ownedPeerRoles[f.callerIP] || (policy.Phase != "active" && policy.Phase != "passive") {
		f.phase = "passive"
		return errors.New("unrecognized remote peer")
	}
	f.callerRole = policy.Role
	f.phase = policy.Phase
	return nil
}
func (f *fixture) changePeerPolicy(ip, phase string) error {
	policy, ok := f.remote.Peers[ip]
	if !ok || (ip != "10.203.11.21" && ip != "10.203.11.22") || (phase != "active" && phase != "passive") {
		return errors.New("only exact seeded green peer mutation policies may change")
	}
	policy.Phase = phase
	f.remote.Peers[ip] = policy
	return nil
}

// Policy is replayed from the immutable seed and root-only controller journal.
// It authorizes API operations; it never asserts that a product node activated.
func (f *fixture) auditPeerHistory(requirePassive bool) error {
	if f.config.Contract == nil || len(f.config.Contract.Peers) == 0 {
		if requirePassive {
			return errors.New("installed caller evidence absent")
		}
		return nil
	}
	policies := map[string]peerPolicy{}
	for ip, p := range f.config.Contract.Peers {
		policies[ip] = p
	}
	observed := map[string]bool{}
	for _, event := range f.remote.Events {
		if event.Protocol == "controller" {
			if event.Method != "SCENARIO" || event.Status != 0 || event.PeerIP != "" || event.PeerRole != "" {
				return errors.New("invalid controller policy journal")
			}
			if event.Target == "peer-active" || event.Target == "peer-passive" {
				var change struct {
					Peer  string `json:"peer"`
					Phase string `json:"phase"`
				}
				if strictJSON(event.Observation, &change) != nil || (change.Peer != "10.203.11.21" && change.Peer != "10.203.11.22") || change.Phase != strings.TrimPrefix(event.Target, "peer-") || event.BodySHA256 != digestBytes([]byte(change.Peer)) {
					return errors.New("unbound peer policy change")
				}
				p, ok := policies[change.Peer]
				if !ok {
					return errors.New("unseeded peer policy change")
				}
				p.Phase = change.Phase
				policies[change.Peer] = p
			}
			continue
		}
		p, known := policies[event.PeerIP]
		success := (event.Protocol == "http" && (event.Status == 200 || event.Status == 0)) || (event.Protocol == "grpc" && event.Status == 0)
		if !known {
			if success || event.PeerRole != "" {
				return errors.New("unrecognized peer accepted")
			}
			continue
		}
		if p.Role != event.PeerRole || p.Phase != event.Phase {
			return errors.New("observed peer differs from recorded policy")
		}
		if requirePassive && p.Phase == "passive" && strings.HasPrefix(p.Role, "green-") {
			read := event.Protocol == "http" && event.Method == "GET" || event.Protocol == "grpc" && event.Target == kmsService+"GetPublicKey"
			if !read {
				return errors.New("passive green attempted a remote mutation")
			}
		}
		if p.Phase == "passive" && success {
			read := event.Protocol == "http" && event.Method == "GET" || event.Protocol == "grpc" && event.Target == kmsService+"GetPublicKey"
			if !read {
				return errors.New("passive peer performed remote mutation")
			}
			if strings.HasPrefix(p.Role, "green-") {
				observed[event.PeerIP] = true
			}
		}
	}
	if !sameJSON(policies, f.remote.Peers) {
		return errors.New("peer policy changed without controller evidence")
	}
	if requirePassive && (!observed["10.203.11.21"] || !observed["10.203.11.22"]) {
		return errors.New("both green passive read observations required")
	}
	return nil
}
