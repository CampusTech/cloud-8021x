package main

import (
	"strings"
	"testing"

	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
)

func candidateFixture() (plan, seed.Input, candidateIndex) {
	p := validPlan()
	s := seed.Input{Project: "task11-acceptance", Credentials: seed.Credentials("task11-acceptance")}
	idx := candidateIndex{Files: map[string]candidate{}, References: map[string][]reference{}}
	for _, n := range p.Nodes {
		set := incoming()
		if strings.HasPrefix(n.Name, "blue-") {
			set = blueDestinations(s)
		}
		for f, v := range set {
			v.SHA256 = strings.Repeat("a", 64)
			idx.Files[n.Name+f] = v
		}
		idx.References[n.Name] = nil
	}
	idx.Files["outer"+controlRoot+"/enrollment.json"] = candidate{strings.Repeat("a", 64), "root", "root", 0600}
	idx.References["outer"] = nil
	return p, s, idx
}
func TestCandidateAuthorityRejectsReceiptsSharedPrivateStateAndBadMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*candidateIndex)
	}{
		{"receipt", func(i *candidateIndex) {
			i.Files["green-primary/var/lib/cloud-8021x/parallel-active.json"] = candidate{strings.Repeat("a", 64), "root", "root", 0600}
		}},
		{"shared-private-source", func(i *candidateIndex) {
			v := i.Files["outer"+controlRoot+"/enrollment.json"]
			delete(i.Files, "outer"+controlRoot+"/enrollment.json")
			i.Files["green-primary/var/lib/cloud-8021x/receipt-key"] = v
		}},
		{"public-secret", func(i *candidateIndex) {
			n := "blue-primary/etc/cloud8021x-task11-webhook.env"
			v := i.Files[n]
			v.Mode = 0644
			i.Files[n] = v
		}},
		{"wrong-owner", func(i *candidateIndex) {
			n := "blue-primary/etc/cloud8021x-task11-webhook.env"
			v := i.Files[n]
			v.Owner = "cloud8021x"
			i.Files[n] = v
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, s, i := candidateFixture()
			tc.edit(&i)
			if validateCandidateIndex(p, s, i) == nil {
				t.Fatal("unapproved candidate authority accepted")
			}
		})
	}
	p, s, i := candidateFixture()
	if e := validateCandidateIndex(p, s, i); e != nil {
		t.Fatal(e)
	}
}
