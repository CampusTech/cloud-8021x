package main

import (
	"errors"
)

type platformFacts struct {
	Linux, Root, Systemd, Marker, Container bool
	Links                                   []string
	Existing                                bool
}

func validatePlatform(f platformFacts, assembled bool) error {
	if !f.Linux || !f.Root || !f.Systemd || !f.Marker || f.Container {
		return errors.New("owned zero-NIC Linux outer PID1 required")
	}
	if !assembled && (f.Existing || len(f.Links) != 1 || f.Links[0] != "lo") {
		return errors.New("preexisting or incomplete assembly refused")
	}
	allowed := map[string]bool{"lo": true}
	if assembled {
		allowed["c8021x11"] = true
		for _, e := range endpoints(plan{Nodes: fixedNodes()}) {
			allowed[e.Name+"-h"] = true
		}
	}
	for _, n := range f.Links {
		if !allowed[n] {
			return errors.New("foreign interface refused")
		}
	}

	return nil
}
