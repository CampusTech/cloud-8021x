package main

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

func companionFixture(t *testing.T) map[string]interface{} {
	t.Helper()
	content, err := os.ReadFile("../../datadog-dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	var dashboard map[string]interface{}
	if err := json.Unmarshal(content, &dashboard); err != nil {
		t.Fatal(err)
	}
	return dashboard
}

func TestCompanionDocumentsProviderLossAndCannotDeploy(t *testing.T) {
	source, losses, err := buildCompanion(companionFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	_, diags := hclsyntax.ParseConfig(source, "companion.tf", hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		t.Fatal(diags.Error())
	}
	for _, expected := range []string{"DO NOT APPLY", "count = 0", "https://github.com/DataDog/terraform-provider-datadog/pull/4225", "should_exclude_missing", "defaults", "log_stream_definition"} {
		if !bytes.Contains(source, []byte(expected)) {
			t.Errorf("generated companion lacks %q", expected)
		}
	}
	if bytes.Contains(source, []byte(`"@timestamp"`)) {
		t.Fatal("companion reintroduces the duplicate date field")
	}
	if bytes.Contains(source, []byte("jsonencode(")) {
		t.Fatal("companion must contain ordinary native HCL blocks")
	}
	var report companionLossReport
	if err := json.Unmarshal(losses, &report); err != nil {
		t.Fatal(err)
	}
	if !report.DeploymentBlocked || report.ProviderVersion != "4.25.0" {
		t.Fatalf("incorrect safety report: %s", losses)
	}
	missing := 0
	for _, loss := range report.Losses {
		if strings.HasSuffix(loss.Path, ".should_exclude_missing") {
			missing++
			if loss.Source != false {
				t.Fatalf("unexpected missing-facet flag: %+v", loss)
			}
		}
	}
	if missing != 24 {
		t.Fatalf("expected all 24 current missing-bucket flags in report, found %d", missing)
	}
	second, secondLosses, err := buildCompanion(companionFixture(t))
	if err != nil || !bytes.Equal(source, second) || !bytes.Equal(losses, secondLosses) {
		t.Fatal("companion export is not deterministic")
	}
}

func TestCompanionRejectsUnrecognizedLoss(t *testing.T) {
	dashboard := companionFixture(t)
	widget := dashboard["widgets"].([]interface{})[0].(map[string]interface{})
	definition := widget["definition"].(map[string]interface{})
	definition["future_behavior_flag"] = true
	if _, _, err := buildCompanion(dashboard); err == nil || !strings.Contains(err.Error(), "future_behavior_flag") {
		t.Fatalf("new unsupported behavior must stop generation, got %v", err)
	}
}

func TestCompanionPreservesExplicitZerosAndFormulaOrder(t *testing.T) {
	source, _, err := buildCompanion(companionFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"formula_expression", "custom {", "timestamp"} {
		if !bytes.Contains(source, []byte(expected)) {
			t.Errorf("companion lost modeled field %q", expected)
		}
	}
	for _, expected := range []string{`(?m)^\s*precision\s*=\s*0$`, `(?m)^\s*index\s*=\s*0$`, `(?m)^\s*autoscale\s*=\s*false$`, `(?m)^\s*show_tick\s*=\s*false$`, `(?m)^\s*label\s*=\s*"hours"$`} {
		if !regexp.MustCompile(expected).Match(source) {
			t.Errorf("companion lost modeled zero or unit matching %q", expected)
		}
	}
}

func TestCompanionAcceptsModernLogListStreams(t *testing.T) {
	var dashboard map[string]interface{}
	if err := json.Unmarshal([]byte(`{
  "title":"Modern logs", "layout_type":"ordered", "widgets":[{
    "definition":{"type":"list_stream", "title":"Authentication", "requests":[{
      "response_format":"event_list",
      "columns":[{"field":"timestamp","width":"auto"},{"field":"@event","width":"auto"}],
      "query":{"data_source":"logs_stream","query_string":"service:radius-auth","indexes":["*"],
               "sort":{"column":"timestamp","order":"desc"}}
    }]}
  }]
}`), &dashboard); err != nil {
		t.Fatal(err)
	}
	source, report, err := buildCompanion(dashboard)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(source, []byte("list_stream_definition")) || bytes.Contains(source, []byte(`"@timestamp"`)) {
		t.Fatal("modern log list stream was changed")
	}
	var losses companionLossReport
	if err := json.Unmarshal(report, &losses); err != nil || len(losses.Losses) != 0 {
		t.Fatalf("unexpected list-stream loss report: %s (%v)", report, err)
	}
}
