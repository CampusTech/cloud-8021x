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
	t.Setenv("WEBHOOK_SIGNING_SECRET", "sec")
	t.Setenv("FLEET_API_BASE_URL", "https://fleet.example")
	t.Setenv("FLEET_API_TOKEN", "tok")
	t.Setenv("PORT", "")
	c, _ := Load()
	if c.Port != "8080" {
		t.Fatalf("default port want 8080 got %s", c.Port)
	}
}
