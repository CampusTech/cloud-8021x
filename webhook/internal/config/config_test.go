package config

import "testing"

func TestLoad_RequiredMissing(t *testing.T) {
	t.Setenv("WEBHOOK_SIGNING_SECRET", "")
	t.Setenv("FLEET_API_BASE_URL", "")
	t.Setenv("FLEET_API_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error when required vars missing")
	}
}

func TestLoad_OK(t *testing.T) {
	t.Setenv("WEBHOOK_CLIENT_DNS_NAMES", "ca.example.com,scep.example.com")
	t.Setenv("WEBHOOK_SIGNING_SECRET", "sec")
	t.Setenv("FLEET_API_BASE_URL", "https://fleet.example")
	t.Setenv("FLEET_API_TOKEN", "tok")
	t.Setenv("ALLOW_LABEL", "test-pilots")
	t.Setenv("PORT", "9000")
	c, err := Load()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if c.Port != "9000" || c.AllowLabel != "test-pilots" || c.FleetBaseURL != "https://fleet.example" {
		t.Fatalf("got %#v", c)
	}
}

func TestLoad_PortDefault(t *testing.T) {
	t.Setenv("WEBHOOK_CLIENT_DNS_NAMES", "ca.example.com,scep.example.com")
	t.Setenv("WEBHOOK_SIGNING_SECRET", "sec")
	t.Setenv("FLEET_API_BASE_URL", "https://fleet.example")
	t.Setenv("FLEET_API_TOKEN", "tok")
	t.Setenv("PORT", "")
	c, _ := Load()
	if c.Port != "8080" {
		t.Fatalf("default port want 8080 got %s", c.Port)
	}
}

func TestLoad_SCEPKey(t *testing.T) {
	t.Setenv("WEBHOOK_CLIENT_DNS_NAMES", "ca.example.com,scep.example.com")
	t.Setenv("WEBHOOK_SIGNING_SECRET", "webhook-secret")
	t.Setenv("FLEET_API_BASE_URL", "https://fleet.example")
	t.Setenv("FLEET_API_TOKEN", "token")
	t.Setenv("SMALLSTEP_SCEP_CHALLENGE", "old-shared-password")
	t.Setenv("SCEP_CHALLENGE_SIGNING_KEY", "short")
	if _, err := Load(); err == nil {
		t.Fatal("short signing key must fail startup")
	}
}

func TestLoadRequiresCAClientNames(t *testing.T) {
	t.Setenv("WEBHOOK_SIGNING_SECRET", "old-secret")
	t.Setenv("FLEET_API_BASE_URL", "https://fleet.example")
	t.Setenv("FLEET_API_TOKEN", "token")
	t.Setenv("WEBHOOK_CLIENT_DNS_NAMES", "")
	if _, err := Load(); err == nil {
		t.Fatal("mTLS must require the allowed CA client identity")
	}
}

func TestInventoryModeRequiresCompleteBrokerConfiguration(t *testing.T) {
	t.Setenv("WEBHOOK_CLIENT_DNS_NAMES", "ca.example.com")
	t.Setenv("FLEET_API_BASE_URL", "https://fleet.example")
	t.Setenv("FLEET_API_TOKEN", "token")
	t.Setenv("SCEP_CERTIFICATE_INVENTORY", "true")
	t.Setenv("SCEP_CHALLENGE_SIGNING_KEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("SCEP_BROKER_USERNAME", "fleet")
	t.Setenv("SCEP_BROKER_TOKEN", "0123456789abcdef0123456789abcdef")
	t.Setenv("SCEP_BROKER_SCEP_URL", "https://scep.example/scep/wifi-scep")
	t.Setenv("SCEP_BROKER_PROVISIONER", "wifi-scep")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SCEPCertificateInventory || cfg.SCEPBrokerPort != "9081" {
		t.Fatal("inventory broker not enabled on its separate port")
	}
	for _, variable := range []string{"SCEP_CHALLENGE_SIGNING_KEY", "SCEP_BROKER_USERNAME", "SCEP_BROKER_TOKEN", "SCEP_BROKER_SCEP_URL", "SCEP_BROKER_PROVISIONER"} {
		t.Run(variable, func(t *testing.T) {
			t.Setenv(variable, "")
			if _, err := Load(); err == nil {
				t.Fatal("missing required broker configuration accepted")
			}
		})
	}
	for _, value := range []string{"yes", "TRUE", "1"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("SCEP_CERTIFICATE_INVENTORY", value)
			if _, err := Load(); err == nil {
				t.Fatal("ambiguous inventory opt-in accepted")
			}
		})
	}
	t.Run("wrong provisioner URL", func(t *testing.T) {
		t.Setenv("SCEP_BROKER_PROVISIONER", "other")
		if _, err := Load(); err == nil {
			t.Fatal("URL/provisioner mismatch accepted")
		}
	})
	t.Run("weak broker password", func(t *testing.T) {
		t.Setenv("SCEP_BROKER_TOKEN", "weak")
		if _, err := Load(); err == nil {
			t.Fatal("weak password accepted")
		}
	})
	t.Run("invalid port", func(t *testing.T) {
		t.Setenv("SCEP_BROKER_PORT", "../9081")
		if _, err := Load(); err == nil {
			t.Fatal("invalid port accepted")
		}
	})
	t.Run("port conflict", func(t *testing.T) {
		t.Setenv("SCEP_BROKER_PORT", "8080")
		t.Setenv("PORT", "8080")
		if _, err := Load(); err == nil {
			t.Fatal("conflicting ports accepted")
		}
	})
}
