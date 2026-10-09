package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every actual mocked fixture starts without repository or user provider caches.
// Keeping this isolation in the regression prevents a developer's warm checkout
// from hiding the missing-init failure seen on CI.
func isolatedTerraformFixture(t *testing.T, module string, args ...string) *exec.Cmd {
	t.Helper()
	dir := t.TempDir()
	cliConfig := filepath.Join(dir, "terraform.rc")
	if err := os.WriteFile(cliConfig, []byte("provider_installation { direct {} }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	env := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TF_") {
			env = append(env, entry)
		}
	}
	env = append(env, "TF_DATA_DIR="+filepath.Join(dir, "data"), "TF_CLI_CONFIG_FILE="+cliConfig, "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1")
	lockPath := filepath.Join(module, ".terraform.lock.hcl")
	lock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		current, err := os.ReadFile(lockPath)
		if err != nil || string(current) != string(lock) {
			t.Error("mocked fixture modified the reviewed provider lock")
		}
	})
	init := exec.Command("terraform", "-chdir="+module, "init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color")
	init.Env = env
	if output, err := init.CombinedOutput(); err != nil {
		t.Fatalf("initialize isolated mocked fixture: %v: %s", err, output)
	}
	cmd := exec.Command("terraform", append([]string{"-chdir=" + module}, args...)...)
	cmd.Env = env
	return cmd
}

func TestGreenPhysicalHostsReachActualDashboardDefaultSelection(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := isolatedTerraformFixture(t, filepath.Join(root, "terraform/green"), "test", "-var-file=tests/fixtures/fixture.tfvars.json", "-json", "-verbose")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("synthetic green configs: %v: %s", err, raw)
	}
	var hosts []string
	for _, line := range strings.Split(string(raw), "\n") {
		var event struct {
			Run  string `json:"@testrun"`
			Plan struct {
				Outputs map[string]json.RawMessage `json:"output_changes"`
			} `json:"test_plan"`
		}
		if json.Unmarshal([]byte(line), &event) != nil || event.Run != "new_green_plan" {
			continue
		}
		if len(event.Plan.Outputs["rendered_config"]) == 0 {
			continue
		}
		var rendered struct {
			After map[string]string `json:"after"`
		}
		if err := json.Unmarshal(event.Plan.Outputs["rendered_config"], &rendered); err != nil {
			t.Fatal(err)
		}
		for _, config := range rendered.After {
			match := regexp.MustCompile(`(?m)^"hostname": "([^"]+)"$`).FindStringSubmatch(config)
			if len(match) != 2 {
				t.Fatal("physical hostname absent from actual rendered YAML")
			}
			hosts = append(hosts, match[1])
		}
	}
	sort.Strings(hosts)
	if !reflect.DeepEqual(hosts, []string{"green-test-primary", "green-test-secondary"}) {
		t.Fatalf("physical host identities: %v", hosts)
	}
	for _, staged := range []bool{false, true} {
		admitted := append([]string(nil), hosts...)
		if staged {
			admitted = append(admitted, "radius-primary", "radius-secondary")
		}
		t.Run(map[bool]string{false: "green_only", true: "staged_pair"}[staged], func(t *testing.T) {
			config, err := isolatedDashboardConfig(root)
			if err != nil {
				t.Fatal(err)
			}
			config = []byte(strings.ReplaceAll(string(config), `{ "radius-primary" = "radius-primary", "radius-secondary" = "radius-secondary" }`, "local.datadog_radius_hosts"))
			hostname, err := os.ReadFile(filepath.Join(root, "datadog-hostname.tf"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(hostname), `variable "datadog_observability_hosts"`) {
				hostname = append(hostname, []byte("\nvariable \"datadog_observability_hosts\" { type = set(string) }\n")...)
			}
			hostname = []byte(strings.NewReplacer("google_project.this.project_id", `"synthetic"`, "google_compute_instance.radius.name", `"radius-primary"`, "google_compute_instance.radius_secondary.name", `"radius-secondary"`).Replace(string(hostname)))
			dir := t.TempDir()
			if err = os.WriteFile(filepath.Join(dir, "main.tf"), append(config, hostname...), 0600); err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(map[string]any{"datadog_hostname_suffix": "", "datadog_observability_hosts": admitted})
			if err = os.WriteFile(filepath.Join(dir, "terraform.tfvars.json"), input, 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("terraform", "console", "-no-color")
			cmd.Dir = dir
			cmd.Stdin = strings.NewReader("jsonencode(local.dashboard_json)\n")
			out, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			var encoded string
			if err = json.Unmarshal(out, &encoded); err != nil {
				t.Fatal(err)
			}
			var dashboard map[string]any
			if err = json.Unmarshal([]byte(encoded), &dashboard); err != nil {
				t.Fatal(err)
			}
			for _, variable := range dashboard["template_variables"].([]any) {
				v := variable.(map[string]any)
				if v["name"] != "host" {
					continue
				}
				if !reflect.DeepEqual(v["defaults"], []any{"*"}) {
					t.Fatal("default host selection changed")
				}
				values := v["available_values"].([]any)
				for _, host := range admitted {
					found := false
					for _, value := range values {
						found = found || value == host
					}
					if !found {
						t.Errorf("actual physical host %s absent from dashboard selector", host)
					}
				}
			}
			// Every actual auth/accounting/usage query keeps the hard host allowlist
			// even when the template selector is *. Evaluate its literal host members.
			checked := 0
			var visit func(any)
			visit = func(value any) {
				switch v := value.(type) {
				case map[string]any:
					for _, child := range v {
						visit(child)
					}
				case []any:
					for _, child := range v {
						visit(child)
					}
				case string:
					if !strings.Contains(v, "host:$host.value") {
						return
					}
					checked++
					actual := regexp.MustCompile(`host:([a-z0-9][a-z0-9.-]+)`).FindAllStringSubmatch(v, -1)
					allowed := map[string]bool{}
					for _, match := range actual {
						allowed[match[1]] = true
					}
					for _, host := range admitted {
						if !allowed[host] {
							t.Errorf("default * query excludes %s: %s", host, v)
						}
					}
					if allowed["unreviewed-primary"] || (!staged && allowed["radius-primary"]) {
						t.Errorf("query admits unreviewed deployment: %s", v)
					}
				}
			}
			visit(dashboard)
			if checked < 10 {
				t.Fatalf("too few actual filtered queries: %d", checked)
			}
		})
	}
}

func TestObservabilityGeneratorClosedDeterministicSource(t *testing.T) {
	files, err := observabilityFiles("../..")
	if err != nil {
		t.Fatal(err)
	}
	again, err := observabilityFiles("../..")
	if err != nil || !reflect.DeepEqual(files, again) {
		t.Fatal("generation is not deterministic")
	}
	source := string(files["observability.tf"])
	for _, forbidden := range []string{"google_", "secret_data", "datadog_api_key", "datadog_app_key", `resource "datadog_dashboard_v2"`} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("unexpected owner dependency %s", forbidden)
		}
	}
	if !strings.Contains(source, "nullable = false") || !strings.Contains(string(files["versions.tf"]), `version = "= 4.25.0"`) {
		t.Fatal("explicit host input/provider pin absent")
	}
	dir := t.TempDir()
	for _, name := range observabilitySources {
		data, err := os.ReadFile(filepath.Join("../..", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "datadog.tf")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, unsupported := range []string{`locals { escaped_loop = host }`, `locals { secret = file("/never-read") }`, `locals { unknown = data.google_secret_manager_secret_version.real.secret_data }`, `resource "datadog_monitor" "unreviewed" { count = 1 }`} {
		if err = os.WriteFile(path, append(append([]byte(nil), original...), []byte("\n"+unsupported)...), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = observabilityFiles(dir); err == nil {
			t.Fatalf("unsupported expression accepted: %s", unsupported)
		}
	}
}

func TestObservabilityPlanPreservesExactOwnership(t *testing.T) {
	files, err := observabilityFiles("../..")
	if err != nil {
		t.Fatal(err)
	}
	var handoff map[string]any
	if err = json.Unmarshal(files["ownership-handoff.json"], &handoff); err != nil {
		t.Fatal(err)
	}
	resources := handoff["resources"].([]any)
	for i, resource := range resources {
		resource.(map[string]any)["existing_remote_id"] = nil
		if i == 0 {
			resource.(map[string]any)["existing_remote_id"] = "existing-radius-id"
		}
	}
	reviewed, _ := json.Marshal(handoff)
	address := observabilityAddresses[0] + "[0]"
	plan := func(actions []string, before, after, address string) []byte {
		data, _ := json.Marshal(map[string]any{"resource_changes": []any{map[string]any{"address": address, "mode": "managed", "change": map[string]any{"actions": actions, "before": map[string]any{"id": before}, "after": map[string]any{"id": after}}}}})
		return data
	}
	if err = checkObservabilityPlan(plan([]string{"update"}, "existing-radius-id", "existing-radius-id", address), reviewed); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		plan([]string{"create"}, "", "new-id", address), plan([]string{"delete"}, "existing-radius-id", "", address), plan([]string{"delete", "create"}, "existing-radius-id", "existing-radius-id", address),
		plan([]string{"update"}, "wrong-id", "wrong-id", address), plan([]string{"update"}, "existing-radius-id", "existing-radius-id", "google_compute_instance.radius"),
	} {
		if checkObservabilityPlan(invalid, reviewed) == nil {
			t.Fatal("unsafe ownership change accepted")
		}
	}
	if checkObservabilityPlan(plan([]string{"update"}, "existing-radius-id", "existing-radius-id", address), files["ownership-handoff.json"]) == nil {
		t.Fatal("unfilled handoff accepted")
	}
}

func TestObservabilityActualMockedOwnerPlan(t *testing.T) {
	cmd := isolatedTerraformFixture(t, "../../terraform/observability", "test", "-json", "-verbose")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("mocked owner fixture: %v: %s", err, raw)
	}
	var selected json.RawMessage
	for _, line := range strings.Split(string(raw), "\n") {
		var event struct {
			Run  string          `json:"@testrun"`
			Plan json.RawMessage `json:"test_plan"`
		}
		if json.Unmarshal([]byte(line), &event) == nil && event.Run == "existing_owner_plan" && len(event.Plan) > 0 {
			selected = event.Plan
		}
	}
	if len(selected) == 0 {
		t.Fatal("actual mock owner plan absent")
	}
	var plan struct {
		Changes []struct {
			Address string `json:"address"`
			Change  struct {
				Before map[string]any `json:"before"`
			} `json:"change"`
		} `json:"resource_changes"`
	}
	if err = json.Unmarshal(selected, &plan); err != nil {
		t.Fatal(err)
	}
	ids := map[string]any{}
	for _, resource := range plan.Changes {
		ids[resource.Address] = resource.Change.Before["id"]
	}
	files, err := observabilityFiles("../..")
	if err != nil {
		t.Fatal(err)
	}
	var handoff map[string]any
	if err = json.Unmarshal(files["ownership-handoff.json"], &handoff); err != nil {
		t.Fatal(err)
	}
	for _, entry := range handoff["resources"].([]any) {
		item := entry.(map[string]any)
		item["existing_remote_id"] = ids[item["source_address"].(string)]
	}
	reviewed, _ := json.Marshal(handoff)
	if err = checkObservabilityPlan(selected, reviewed); err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 15 {
		t.Fatalf("expected exact active owner set (issuance monitor disabled), got %d", len(plan.Changes))
	}
}
