package contract

import (
	"strings"
	"testing"
	"time"
)

func TestRejectUnboundAssemblyInput(t *testing.T) {
	input := Input{Schema: 1, Project: "task11-acceptance", ProjectNumber: ProjectNumber, SQLInstance: "task11-acceptance:us-central1:task11-postgres", ObservedAt: time.Unix(1800000000, 0).UTC(), CollectionEpoch: time.Unix(1800000100, 0).UTC()}
	for _, mutate := range []func(*Input){func(i *Input) { i.PostgresCA.Path = "../../secret" }, func(i *Input) { i.Project = "production-project" }, func(i *Input) {
		i.Credentials = []Credential{{ID: "bad", File: "/run/cloud-8021x/credentials/webhook.key", Owner: "runtime"}}
	}, func(i *Input) { i.InstalledSeedSHA256 = strings.Repeat("0", 64) }} {
		candidate := input
		mutate(&candidate)
		if candidate.Validate() == nil {
			t.Fatal("incomplete or unbound assembly input accepted")
		}
	}
}
