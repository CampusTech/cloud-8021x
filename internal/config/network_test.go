package config

import (
	"testing"
	"time"
)

func TestSingleUniFiKeyAndPinnedSourceBindings(t *testing.T) {
	base := Config{Network: Network{Providers: []NetworkProvider{{ID: "u", Kind: "unifi", ConsoleID: "console", Credential: SecretRef{File: "/run/key"}, Scopes: []string{"office"}}, {ID: "home", Kind: "unifi", ConsoleID: "home-console", Credential: SecretRef{File: "/run/key"}, Scopes: []string{"home-site"}}}, Locations: []Location{{ID: "nyc", ProviderID: "u", SiteID: "office"}}, Discovery: Discovery{Enabled: true, MaxAge: time.Minute, CandidateFile: "/run/cloud8021x/sources.json", Bindings: []SourceBinding{{ProviderID: "u", ClientID: "client"}}, Firewall: SourceFirewall{Project: "synthetic-project", Node: "radius-primary", Network: "https://www.googleapis.com/compute/v1/projects/synthetic-project/global/networks/vpc"}}}, RadiusClients: []RadiusClient{{ID: "client", LocationID: "nyc"}}}
	if e := validateNetworkDetails(base); e != nil {
		t.Fatal(e)
	}
	base.Network.Providers[1].Credential.File = "/run/other-key"
	if e := validateNetworkDetails(base); e == nil {
		t.Fatal("multiple UniFi keys allowed")
	}
	base.Network.Providers[1].Credential.File = "/run/key"
	base.Network.Discovery.Bindings[0].ClientID = "unknown"
	if e := validateNetworkDetails(base); e == nil {
		t.Fatal("unknown client accepted")
	}
	base.Network.Discovery.Bindings[0].ClientID = "client"
	base.Network.Discovery.Firewall.Node = "other-node"
	if e := validateNetworkDetails(base); e == nil {
		t.Fatal("arbitrary firewall target accepted")
	}
}
