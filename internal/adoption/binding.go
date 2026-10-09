package adoption

import (
	"encoding/json"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

// ExpectedBinding constructs the complete signed source/destination contract.
// Each trust boundary must still independently verify its signature.
func ExpectedBinding(c config.Config, release string) (Binding, error) {
	manifest, err := c.ParallelManifest()
	if err != nil {
		return Binding{}, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return Binding{}, err
	}
	source := c.Deployment.SourcePrimary
	if c.InstanceID == "radius-secondary" {
		source = c.Deployment.SourceSecondary
	}
	return Binding{Transition: c.StateTransition, ManifestSHA256: manifest, ConfigSHA256: Digest(raw), ReleaseSHA256: release, SourceDeployment: c.Deployment.SourceID, SourceInstance: source, Deployment: c.Deployment.ID, Instance: c.Deployment.Instance, Role: c.InstanceID, CollectionEpoch: c.Deployment.CollectionEpoch}, nil
}
