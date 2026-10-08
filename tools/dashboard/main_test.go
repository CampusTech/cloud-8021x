package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/terraform-providers/terraform-provider-datadog/datadog/dashboardmapping"
)

func TestExportNativePlannedDashboard(t *testing.T) {
	dir := t.TempDir()
	plan := filepath.Join(dir, "plan.json")
	output := filepath.Join(dir, "dashboard.json")
	input := `{"planned_values":{"root_module":{"resources":[{"address":"datadog_dashboard_v2.radius[0]","type":"datadog_dashboard_v2","values":{"title":"Dashboard","layout_type":"ordered","widget":[]}}]}}}`
	if err := os.WriteFile(plan, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	command := newCommand()
	command.SetArgs([]string{"--plan", plan, "--output", output})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var dashboard map[string]interface{}
	if err := json.Unmarshal(content, &dashboard); err != nil {
		t.Fatal(err)
	}
	if dashboard["title"] != "Dashboard" || dashboard["layout_type"] != "ordered" {
		t.Fatalf("unexpected dashboard: %s", content)
	}
	if _, exists := dashboard["id"]; exists {
		t.Fatal("volatile dashboard ID leaked")
	}
}

// This fixture stays tied to the checked-in export so changing any actual query,
// layout, log timestamp, or explicit zero must survive the official roundtrip.
func TestCurrentDashboardProviderRoundtrip(t *testing.T) {
	content, err := os.ReadFile("../../datadog-dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	var original map[string]interface{}
	if err := json.Unmarshal(content, &original); err != nil {
		t.Fatal(err)
	}
	widgets, drops := dashboardmapping.FlattenWidgetsForSDKv2(original["widgets"].([]interface{}))
	if len(drops) != 0 {
		t.Fatalf("provider dropped fields: %v", drops)
	}
	values := dashboardmapping.FlattenEngineJSON(dashboardmapping.DashboardTopLevelFields, original)
	values["widget"] = widgets
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	writePlan(t, planPath, "datadog_dashboard_v2.radius[0]", "datadog_dashboard_v2", values, nil, false)
	command := newCommand()
	command.SetErr(io.Discard)
	output := filepath.Join(dir, "export.json")
	command.SetArgs([]string{"--plan", planPath, "--output", output})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	builtContent, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var built map[string]interface{}
	if err := json.Unmarshal(builtContent, &built); err != nil {
		t.Fatal(err)
	}
	// Provider v4.25.0 silently lacks this logs-query field, which blocks the
	// production native migration. Keep an explicit regression for the gap.
	assertAndRemoveMissingFacetFlags(t, original, built)
	for key, value := range original {
		if difference := firstDifference(value, originalShape(value, built[key]), "$."+key); difference != "" {
			t.Fatalf("roundtrip changed %s", difference)
		}
	}

	// Confirm the fixture really exercises the fragile API fields.
	for _, field := range []string{`"index": 0`, `"queries"`, `"facet"`, `"layout"`, `"timestamp"`, `"show_tick": false`} {
		if !bytes.Contains(content, []byte(field)) {
			t.Fatalf("fixture lacks %s", field)
		}
	}
}

func assertAndRemoveMissingFacetFlags(t *testing.T, original, built interface{}) {
	t.Helper()
	switch value := original.(type) {
	case map[string]interface{}:
		other, _ := built.(map[string]interface{})
		for key, child := range value {
			if value["type"] == "sunburst" && (key == "description" || (key == "hide_total" && child == false)) {
				delete(value, key)
				continue
			}
			if key == "should_exclude_missing" {
				if child != false {
					t.Fatal("fixture missing-facet flag must be explicit false")
				}
				if _, exists := other[key]; exists {
					t.Fatal("provider now supports missing facets: remove the migration blocker and update this regression")
				}
				delete(value, key)
				continue
			}
			assertAndRemoveMissingFacetFlags(t, child, other[key])
		}
	case []interface{}:
		other, _ := built.([]interface{})
		if len(value) != len(other) {
			t.Fatal("widget array changed")
		}
		for index, child := range value {
			assertAndRemoveMissingFacetFlags(t, child, other[index])
		}
	}
}

func TestSyncIsolatedLocals(t *testing.T) {
	if _, err := exec.LookPath("terraform"); err != nil {
		t.Skip("Terraform unavailable")
	}
	dir := t.TempDir()
	t.Setenv("TF_CLI_ARGS_plan", "-target=google_compute_instance.production")
	t.Setenv("TF_DATA_DIR", filepath.Join(dir, "real-terraform-data"))
	if err := os.WriteFile(filepath.Join(dir, "datadog.tf"), []byte(`
provider "datadog" { api_key = "never-copy" }
locals {
 datadog_enabled = var.datadog_app_key != ""
 unused_production = google_secret_manager_secret_version.secret.secret_data
 dashboard_json = { title = "RADIUS", layout_type = "ordered", widgets = [], template_variables = [{ name = "host", available_values = [local.datadog_radius_hosts[google_compute_instance.radius.name], local.datadog_radius_hosts["radius-secondary"]] }] }
 smallstep_dashboard_json = { title = "Smallstep", layout_type = "ordered", widgets = [] }
}
resource "google_compute_instance" "radius" { name = "never-copy" }
`), 0600); err != nil {
		t.Fatal(err)
	}
	command := newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"sync", "--root", dir})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(dir, "datadog-dashboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, []byte("radius-primary")) {
		t.Fatalf("canonical host not used: %s", content)
	}
	if !bytes.Contains(content, []byte("radius-secondary")) {
		t.Fatalf("constant host index not preserved: %s", content)
	}
	if _, err := os.Stat(filepath.Join(dir, ".terraform")); !os.IsNotExist(err) {
		t.Fatal("sync initialized real Terraform directory")
	}
	if _, err := os.Stat(filepath.Join(dir, "real-terraform-data")); !os.IsNotExist(err) {
		t.Fatal("sync honored external Terraform data directory")
	}
	command = newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"sync", "--root", dir, "--check"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "docs/generated/datadog-dashboard-v2.tf"))
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte(`{"title":"changed","layout_type":"ordered","widgets":[]}`)
	if err := os.WriteFile(filepath.Join(dir, "datadog-dashboard.json"), changed, 0600); err != nil {
		t.Fatal(err)
	}
	command = newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"sync", "--root", dir, "--check"})
	if err := command.Execute(); err == nil {
		t.Fatal("sync check accepted drift")
	}
	after, err := os.ReadFile(filepath.Join(dir, "docs/generated/datadog-dashboard-v2.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("sync check rewrote companion")
	}
	current, err := os.ReadFile(filepath.Join(dir, "datadog-dashboard.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, changed) {
		t.Fatal("sync check rewrote drifting export")
	}
}

func originalShape(original, built interface{}) interface{} {
	switch value := original.(type) {
	case map[string]interface{}:
		other, _ := built.(map[string]interface{})
		result := map[string]interface{}{}
		for key, child := range value {
			result[key] = originalShape(child, other[key])
		}
		return result
	case []interface{}:
		other, _ := built.([]interface{})
		if len(value) != len(other) {
			return built
		}
		result := make([]interface{}, len(value))
		for index, child := range value {
			result[index] = originalShape(child, other[index])
		}
		return result
	default:
		return built
	}
}

func writePlan(t *testing.T, path, address, resourceType string, values map[string]interface{}, unknown interface{}, child bool) {
	t.Helper()
	resource := map[string]interface{}{"address": address, "type": resourceType, "values": values}
	module := map[string]interface{}{"resources": []interface{}{resource}}
	if child {
		module = map[string]interface{}{"child_modules": []interface{}{module}}
	}
	plan := map[string]interface{}{"planned_values": map[string]interface{}{"root_module": module}}
	if unknown != nil {
		plan["resource_changes"] = []interface{}{map[string]interface{}{"address": address, "change": map[string]interface{}{"after_unknown": unknown}}}
	}
	content, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSemanticEqualityAndDriftDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	planPath, output := filepath.Join(dir, "plan.json"), filepath.Join(dir, "export.json")
	writePlan(t, planPath, "datadog_dashboard_json.smallstep[0]", "datadog_dashboard_json", map[string]interface{}{"dashboard": `{"title":"Smallstep","layout_type":"ordered","widgets":[],"id":"volatile","url":"https://example.test"}`}, nil, true)
	for _, tc := range []struct {
		name, actual string
		wantError    bool
	}{
		{"formatting", ` {"widgets": [], "layout_type":"ordered", "title":"Smallstep"} `, false},
		{"query drift", `{"widgets":[],"layout_type":"ordered","title":"Changed"}`, true},
		{"malformed export", `{`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(output, []byte(tc.actual), 0600); err != nil {
				t.Fatal(err)
			}
			command := newCommand()
			command.SetErr(io.Discard)
			command.SetArgs([]string{"json", "--plan", planPath, "--output", output, "--check"})
			err := command.Execute()
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, want error %v", err, tc.wantError)
			}
			current, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if string(current) != tc.actual {
				t.Fatal("check changed export")
			}
		})
	}
}

func TestRejectUnknownDashboardValuesWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	planPath, output := filepath.Join(dir, "plan.json"), filepath.Join(dir, "export.json")
	writePlan(t, planPath, "datadog_dashboard_v2.radius[0]", "datadog_dashboard_v2", map[string]interface{}{"title": "Dashboard", "layout_type": "ordered", "widget": []interface{}{}}, map[string]interface{}{"widget": []interface{}{map[string]interface{}{"timeseries_definition": []interface{}{map[string]interface{}{"request": true}}}}}, false)
	command := newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"--plan", planPath, "--output", output})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown-value rejection, got %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("unknown values wrote an export")
	}
}

func TestPlanSelectionFailsClosedAndDryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	planPath, output := filepath.Join(dir, "plan.json"), filepath.Join(dir, "export.json")
	resource := `{"address":"datadog_dashboard_v2.radius[0]","type":"datadog_dashboard_v2","values":{"title":"Dashboard","layout_type":"ordered","widget":[]}}`
	for _, tc := range []struct{ name, content string }{
		{"state only", `{"values":{"root_module":{"resources":[` + resource + `]}}}`},
		{"missing address", `{"planned_values":{"root_module":{"resources":[]}}}`},
		{"ambiguous address", `{"planned_values":{"root_module":{"resources":[` + resource + `,` + resource + `]}}}`},
		{"trailing data", `{"planned_values":{"root_module":{"resources":[` + resource + `]}}} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(planPath, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			command := newCommand()
			command.SetErr(io.Discard)
			command.SetArgs([]string{"--plan", planPath, "--output", output})
			if err := command.Execute(); err == nil {
				t.Fatal("invalid plan accepted")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("invalid plan wrote export")
			}
		})
	}
	writePlan(t, planPath, "datadog_dashboard_v2.radius[0]", "datadog_dashboard_v2", map[string]interface{}{"title": "Dashboard", "layout_type": "ordered", "widget": []interface{}{}}, map[string]interface{}{"id": true, "url": true}, true)
	command := newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"--plan", planPath, "--output", output, "--dry-run"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote export")
	}
}

func TestNestedUnknownURLIsNotComputedDashboardMetadata(t *testing.T) {
	dir := t.TempDir()
	planPath, output := filepath.Join(dir, "plan.json"), filepath.Join(dir, "export.json")
	writePlan(t, planPath, "datadog_dashboard_v2.radius[0]", "datadog_dashboard_v2", map[string]interface{}{"title": "Dashboard", "layout_type": "ordered", "widget": []interface{}{}}, map[string]interface{}{"widget": []interface{}{map[string]interface{}{"iframe_definition": []interface{}{map[string]interface{}{"url": true}}}}}, false)
	command := newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"--plan", planPath, "--output", output})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("nested unknown URL must reject export, got %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("nested unknown URL wrote an export")
	}
}

func TestUnknownComputedWidgetIDsDoNotPreventCreatePlanExport(t *testing.T) {
	dir := t.TempDir()
	planPath, output := filepath.Join(dir, "plan.json"), filepath.Join(dir, "export.json")
	note := map[string]interface{}{"note_definition": []interface{}{map[string]interface{}{"content": "Known note"}}}
	group := map[string]interface{}{"group_definition": []interface{}{map[string]interface{}{"title": "Group", "layout_type": "ordered", "widget": []interface{}{note}}}}
	unknown := map[string]interface{}{"id": true, "url": true, "dashboard_lists_removed": true, "widget": []interface{}{map[string]interface{}{"id": true, "group_definition": []interface{}{map[string]interface{}{"widget": []interface{}{map[string]interface{}{"id": true}}}}}}}
	writePlan(t, planPath, "datadog_dashboard_v2.radius[0]", "datadog_dashboard_v2", map[string]interface{}{"title": "Dashboard", "layout_type": "ordered", "widget": []interface{}{group}}, unknown, false)
	command := newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"--plan", planPath, "--output", output})
	if err := command.Execute(); err != nil {
		t.Fatalf("computed widget IDs must not block create-plan export: %v", err)
	}
	unknown["dashboard_lists"] = true
	writePlan(t, planPath, "datadog_dashboard_v2.radius[0]", "datadog_dashboard_v2", map[string]interface{}{"title": "Dashboard", "layout_type": "ordered", "widget": []interface{}{group}}, unknown, false)
	command = newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"--plan", planPath, "--output", output})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("configured dashboard_lists unknown must be rejected, got %v", err)
	}
}

func TestSyncRejectsFilesystemFunctionsBeforeEvaluation(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel.txt")
	if err := os.WriteFile(sentinel, []byte("dummy-private-title"), 0600); err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf("locals {\n dashboard_json = { title = file(%q), layout_type = \"ordered\", widgets = [] }\n smallstep_dashboard_json = { title = \"Smallstep\", layout_type = \"ordered\", widgets = [] }\n}\n", sentinel)
	if err := os.WriteFile(filepath.Join(dir, "datadog.tf"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	command := newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"sync", "--root", dir})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "filesystem") {
		t.Fatalf("filesystem function must reject isolated sync, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "datadog-dashboard.json")); !os.IsNotExist(err) {
		t.Fatal("filesystem function wrote an export")
	}
}

func TestSyncUsesPrivateEmptyTerraformCLIConfiguration(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	userConfig := filepath.Join(dir, "user.terraformrc")
	if err := os.WriteFile(userConfig, []byte("dummy deployment credential marker"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TF_CLI_CONFIG_FILE", userConfig)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	// The executable rejects any inherited/default CLI configuration. Its
	// successful result verifies every planner invocation receives an empty,
	// private config instead of silently loading the user's Terraform settings.
	script := `#!/bin/sh
[ -n "$TF_CLI_CONFIG_FILE" ] || exit 11
[ -f "$TF_CLI_CONFIG_FILE" ] || exit 12
[ ! -s "$TF_CLI_CONFIG_FILE" ] || exit 13
case "$TF_CLI_CONFIG_FILE" in */dashboard-sync-*/terraform.rc) ;; *) exit 14;; esac
if [ "$1" = show ]; then
 printf '%s\n' '{"planned_values":{"outputs":{"radius":{"value":"{\"title\":\"Radius\",\"layout_type\":\"ordered\",\"widgets\":[]}"},"smallstep":{"value":"{\"title\":\"Smallstep\",\"layout_type\":\"ordered\",\"widgets\":[]}"}}}}'
fi
`
	if err := os.WriteFile(filepath.Join(bin, "terraform"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "datadog.tf"), []byte("locals {\n dashboard_json = { title = \"Radius\", layout_type = \"ordered\", widgets = [] }\n smallstep_dashboard_json = { title = \"Smallstep\", layout_type = \"ordered\", widgets = [] }\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"sync", "--root", dir, "--dry-run"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestNullOptionalZeroDoesNotCreateIndex(t *testing.T) {
	content := []byte(`{"title":"Dashboard","layout_type":"ordered","widgets":[{"definition":{"type":"query_table","requests":[{"response_format":"scalar","queries":[{"data_source":"metrics","name":"a","query":"sum:example{*}"}],"formulas":[{"formula":"a","limit":{"count":5,"order":"desc"}}]}]},"layout":{"x":0,"y":0,"width":6,"height":3}}]}`)
	var original map[string]interface{}
	if err := json.Unmarshal(content, &original); err != nil {
		t.Fatal(err)
	}
	widgets, drops := dashboardmapping.FlattenWidgetsForSDKv2(original["widgets"].([]interface{}))
	if len(drops) > 0 {
		t.Fatal(drops)
	}
	// Terraform emits null for an unset optional formula limit index.
	definition := widgets[0].(map[string]interface{})["query_table_definition"].([]interface{})[0].(map[string]interface{})
	request := definition["request"].([]interface{})[0].(map[string]interface{})
	formula := request["formula"].([]interface{})[0].(map[string]interface{})
	formula["limit"].([]interface{})[0].(map[string]interface{})["index"] = nil
	values := dashboardmapping.FlattenEngineJSON(dashboardmapping.DashboardTopLevelFields, original)
	values["widget"] = widgets
	dir := t.TempDir()
	planPath, output := filepath.Join(dir, "plan.json"), filepath.Join(dir, "export.json")
	writePlan(t, planPath, "datadog_dashboard_v2.radius[0]", "datadog_dashboard_v2", values, nil, false)
	if err := os.WriteFile(output, content, 0600); err != nil {
		t.Fatal(err)
	}
	command := newCommand()
	command.SetErr(io.Discard)
	command.SetArgs([]string{"--plan", planPath, "--output", output})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	builtContent, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var built map[string]interface{}
	if err := json.Unmarshal(builtContent, &built); err != nil {
		t.Fatal(err)
	}
	if difference := firstDifference(original["widgets"], built["widgets"], "$.widgets"); difference != "" {
		t.Fatalf("roundtrip changed %s", difference)
	}
	if !reflect.DeepEqual(formula["limit"].([]interface{})[0].(map[string]interface{})["index"], nil) {
		t.Fatal("fixture unexpectedly mutated")
	}
}
