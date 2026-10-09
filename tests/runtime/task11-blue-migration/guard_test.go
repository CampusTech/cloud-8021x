package main

import (
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestOnlyOriginalBluePrimaryIdentityMayProceed(t *testing.T) {
	good := identity{UID: 0, Marker: "synthetic-only-v1\n", Hostname: "task11-blue-primary", MachineID: strings.Repeat("a", 32), PID1: "systemd\n"}
	for _, mutate := range []func(*identity){func(v *identity) { v.UID = 501 }, func(v *identity) { v.Marker = "" }, func(v *identity) { v.Hostname = "task11-green-primary" }, func(v *identity) { v.Hostname = "task11-blue-secondary" }, func(v *identity) { v.MachineID = strings.Repeat("b", 32) }, func(v *identity) { v.PID1 = "bash" }} {
		v := good
		mutate(&v)
		if validateIdentity(v, good.MachineID) == nil {
			t.Fatal("unapproved physical identity accepted")
		}
	}
	if err := validateIdentity(good, good.MachineID); err != nil {
		t.Fatal(err)
	}
}
func TestDSNDeniesGreenCAAlternateHostRoleAndTLS(t *testing.T) {
	good := "postgresql://cloud8021x_task11_blue_migrate:private-password@10.203.11.11:5432/cloud8021x_task11_blue?sslmode=verify-full"
	for _, bad := range []string{strings.ReplaceAll(good, "task11_blue", "task11_green"), strings.Replace(good, "/cloud8021x_task11_blue?", "/stepca?", 1), strings.Replace(good, "_migrate:", "_runtime:", 1), strings.Replace(good, "10.203.11.11", "127.0.0.1", 1), strings.Replace(good, "verify-full", "disable", 1), good + "&host=10.203.11.12", good + "&sslmode=disable", strings.Replace(good, ":5432", ":5433", 1)} {
		if err := validateDSN([]byte(bad)); err == nil {
			t.Fatal("unapproved DSN accepted")
		} else if strings.Contains(err.Error(), "private-password") {
			t.Fatal("secret disclosed")
		}
	}
	if err := validateDSN([]byte(good)); err != nil {
		t.Fatal(err)
	}
}
func TestConfigurationCannotSelectGreenOrInheritedCADatabases(t *testing.T) {
	c := config.Defaults()
	c.Database.Name = "cloud8021x_task11_green"
	if validateBlueConfig(c, "", "") == nil {
		t.Fatal("green configuration accepted")
	}
	c.Database.Name = "stepca"
	if validateBlueConfig(c, "", "") == nil {
		t.Fatal("CA configuration accepted")
	}
}
