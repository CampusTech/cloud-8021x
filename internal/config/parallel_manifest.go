package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// ParallelManifest binds the common pair configuration without a circular peer
// config digest. Each physical node additionally retains its full config hash.
func (c Config) ParallelManifest() (string, error) {
	if err := c.ValidateDeployment(); err != nil {
		return "", err
	}
	c.InstanceID = ""
	c.Hostname = ""
	c.Deployment.Instance = ""
	addresses := []string{c.Bootstrap.LocalAddress, c.Bootstrap.PeerAddress}
	sort.Strings(addresses)
	c.Bootstrap.LocalAddress = addresses[0]
	c.Bootstrap.PeerAddress = addresses[1]
	c.Bootstrap.PeerDNS = ""
	c.Network.Discovery.Firewall.Node = ""
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
