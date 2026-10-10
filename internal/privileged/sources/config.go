package sources

import "github.com/CampusTech/cloud-8021x/internal/config"

func FromConfig(cfg config.Config) (Config, error) {
	out := Config{MaxAge: cfg.Network.Discovery.MaxAge}
	for _, client := range cfg.RadiusClients {
		b := Binding{ClientID: client.ID, LocationID: client.LocationID, Medium: client.Medium, SignalingProfile: client.SignalingProfile, SecretFile: client.Secret.File, StaticCIDRs: append([]string(nil), client.CIDRs...)}
		for _, binding := range cfg.Network.Discovery.Bindings {
			if binding.ClientID == client.ID {
				for _, p := range cfg.Network.Providers {
					if p.ID == binding.ProviderID {
						b.ProviderID = p.ID
						b.ProviderOrigin = p.BaseURL
						b.ConsoleID = p.ConsoleID
					}
				}
			}
		}
		out.Bindings = append(out.Bindings, b)
	}
	return out, out.Validate()
}
