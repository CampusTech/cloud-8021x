package provisioning

import "testing"

func TestDeploymentDatabaseIdentity(t *testing.T) {
	for _, tc := range []struct{ deployment, database, runtime, native, migration string }{
		{"", "cloud8021x", "cloud8021x_runtime", "cloud8021x_native", "cloud8021x_migrate"},
		{"green-a", "cloud8021x_green_a", "cloud8021x_green_a_runtime", "cloud8021x_green_a_native", "cloud8021x_green_a_migrate"},
	} {
		c := Config{DeploymentID: tc.deployment}
		db, roles, err := c.applicationIdentity()
		if err != nil || db != tc.database || roles != [3]string{tc.runtime, tc.native, tc.migration} {
			t.Fatalf("identity=%s/%v err=%v", db, roles, err)
		}
	}
	for _, id := range []string{"stepca", "-green", "Green", "green';DROP DATABASE stepca;--", "green_foo"} {
		_, _, err := (Config{DeploymentID: id}).applicationIdentity()
		if err == nil {
			t.Fatalf("accepted unsafe/reserved deployment %q", id)
		}
	}
}
