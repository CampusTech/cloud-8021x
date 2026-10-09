package sources

import (
	"errors"
	"regexp"
	"strings"
)

func (t FirewallTarget) Validate() error {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{4,62}$`).MatchString(t.Project) || t.Network == "" {
		return errors.New("invalid fixed firewall project or network")
	}
	if t.Deployment == "" && t.Role == "" && (t.Node == "radius-primary" || t.Node == "radius-secondary") {
		return nil
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,38}[a-z0-9]$`).MatchString(t.Deployment) || (t.Role != "radius-primary" && t.Role != "radius-secondary") || t.Node != t.Deployment+strings.TrimPrefix(t.Role, "radius") {
		return errors.New("firewall target differs from the fixed deployment role mapping")
	}
	return nil
}
