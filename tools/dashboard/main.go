// dashboard exports Datadog dashboards from Terraform's planned values.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/terraform-providers/terraform-provider-datadog/datadog/dashboardmapping"
)

type options struct {
	plan, address, output string
	check, dryRun, debug  bool
}

type planModule struct {
	Resources    []planResource `json:"resources"`
	ChildModules []planModule   `json:"child_modules"`
}

type planResource struct {
	Address string                 `json:"address"`
	Type    string                 `json:"type"`
	Values  map[string]interface{} `json:"values"`
}

type terraformPlan struct {
	PlannedValues *struct {
		RootModule planModule `json:"root_module"`
	} `json:"planned_values"`
	ResourceChanges []struct {
		Address string `json:"address"`
		Change  struct {
			AfterUnknown interface{} `json:"after_unknown"`
		} `json:"change"`
	} `json:"resource_changes"`
}

func main() {
	if err := newCommand().Execute(); err != nil {
		os.Exit(1)
	}
}

func newCommand() *cobra.Command {
	root := exportCommand("dashboard", "datadog_dashboard_v2", "datadog_dashboard_v2.radius[0]", "datadog-dashboard.json")
	root.Short = "Export or check a dashboard from a Terraform plan JSON"
	root.AddCommand(exportCommand("json", "datadog_dashboard_json", "datadog_dashboard_json.smallstep[0]", "datadog-smallstep-dashboard.json"))
	root.AddCommand(syncCommand())
	root.AddCommand(observabilityCommand())
	return root
}

func exportCommand(name, resourceType, address, output string) *cobra.Command {
	opt := options{}
	command := &cobra.Command{Use: name, Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error { return opt.run(cmd.ErrOrStderr(), resourceType) },
	}
	flags := command.Flags()
	flags.StringVar(&opt.plan, "plan", "", "Terraform plan JSON produced by terraform show -json")
	flags.StringVar(&opt.address, "address", address, "Exact planned resource address")
	flags.StringVar(&opt.output, "output", output, "Dashboard JSON export to generate or check")
	flags.BoolVar(&opt.check, "check", false, "Fail on semantic drift without changing the export")
	flags.BoolVar(&opt.dryRun, "dry-run", false, "Report changes without writing the export")
	flags.BoolVar(&opt.debug, "debug", false, "Enable debug logging")
	_ = command.MarkFlagRequired("plan")
	return command
}

func (opt options) run(stderr io.Writer, resourceType string) error {
	logger := logrus.New()
	logger.SetOutput(stderr)
	if opt.debug {
		logger.SetLevel(logrus.DebugLevel)
	}
	log := logger.WithFields(logrus.Fields{"address": opt.address, "plan": opt.plan, "output": opt.output})
	content, err := os.ReadFile(opt.plan)
	if err != nil {
		return fmt.Errorf("read plan: %w", err)
	}
	var plan terraformPlan
	if err := decodeJSON(content, &plan); err != nil {
		return fmt.Errorf("decode plan: %w", err)
	}
	resource, err := selectedResource(plan, opt.address, resourceType)
	if err != nil {
		return err
	}
	values := omitNulls(resource.Values).(map[string]interface{})
	var dashboard map[string]interface{}
	if resourceType == "datadog_dashboard_json" {
		encoded, ok := values["dashboard"].(string)
		if !ok || encoded == "" {
			return errors.New("planned resource has no dashboard JSON")
		}
		if err := decodeJSON([]byte(encoded), &dashboard); err != nil {
			return fmt.Errorf("decode dashboard: %w", err)
		}
	} else {
		if _, ok := values["widget"].([]interface{}); !ok {
			return errors.New("planned resource has no known widget list")
		}
		if conflicts := dashboardmapping.ValidateWidgetConflicts(values); len(conflicts) > 0 {
			return fmt.Errorf("invalid planned widgets: %v", conflicts)
		}
		dashboard = dashboardmapping.BuildDashboardEngineJSONFromMap(values, "")
	}
	if title, _ := dashboard["title"].(string); title == "" {
		return errors.New("planned dashboard has no known title")
	}
	if layout, _ := dashboard["layout_type"].(string); layout == "" {
		return errors.New("planned dashboard has no known layout_type")
	}
	removeMetadata(dashboard)
	encoded, err := json.MarshalIndent(dashboard, "", "  ")
	if err != nil {
		return fmt.Errorf("encode dashboard: %w", err)
	}
	encoded = append(encoded, '\n')
	log.Debug("serialized planned dashboard with the official provider mapping")
	if opt.check || opt.dryRun {
		current, readErr := os.ReadFile(opt.output)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return fmt.Errorf("read export: %w", readErr)
		}
		var expected, actual interface{}
		if err := decodeJSON(encoded, &expected); err != nil {
			return err
		}
		if readErr == nil {
			if err := decodeJSON(current, &actual); err != nil {
				return fmt.Errorf("decode export: %w", err)
			}
		}
		if reflect.DeepEqual(expected, actual) {
			log.Info("dashboard export matches plan")
			return nil
		}
		if opt.check {
			return fmt.Errorf("dashboard export differs from plan: %s (%s)", opt.output, firstDifference(expected, actual, "$"))
		}
		log.Info("dashboard export would change")
		return nil
	}
	if err := os.WriteFile(opt.output, encoded, 0644); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	log.Info("dashboard export updated")
	return nil
}

func firstDifference(expected, actual interface{}, path string) string {
	if reflect.DeepEqual(expected, actual) {
		return ""
	}
	switch typed := expected.(type) {
	case map[string]interface{}:
		other, ok := actual.(map[string]interface{})
		if !ok {
			return path
		}
		keys := make([]string, 0, len(typed)+len(other))
		for key := range typed {
			keys = append(keys, key)
		}
		for key := range other {
			if _, exists := typed[key]; !exists {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			if difference := firstDifference(typed[key], other[key], path+"."+key); difference != "" {
				return difference
			}
		}
	case []interface{}:
		other, ok := actual.([]interface{})
		if !ok || len(typed) != len(other) {
			return path
		}
		for index, value := range typed {
			if difference := firstDifference(value, other[index], fmt.Sprintf("%s[%d]", path, index)); difference != "" {
				return difference
			}
		}
	}
	return path
}

func decodeJSON(content []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	// The provider's mapping engine accepts float64 for Terraform numeric values.
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func selectedResource(plan terraformPlan, address, resourceType string) (planResource, error) {
	if plan.PlannedValues == nil {
		return planResource{}, errors.New("plan has no planned_values")
	}
	var matches []planResource
	var visit func(planModule)
	visit = func(module planModule) {
		for _, resource := range module.Resources {
			if resource.Address == address {
				matches = append(matches, resource)
			}
		}
		for _, child := range module.ChildModules {
			visit(child)
		}
	}
	visit(plan.PlannedValues.RootModule)
	if len(matches) != 1 {
		return planResource{}, fmt.Errorf("expected exactly one planned resource at %q; found %d", address, len(matches))
	}
	resource := matches[0]
	if resource.Type != resourceType {
		return planResource{}, fmt.Errorf("resource %q has type %q, expected %q", address, resource.Type, resourceType)
	}
	if len(resource.Values) == 0 {
		return planResource{}, fmt.Errorf("resource %q has no planned values", address)
	}
	for _, change := range plan.ResourceChanges {
		if change.Address != address {
			continue
		}
		fields := map[string]*schema.Schema{"id": {Computed: true}, "url": {Computed: true}}
		if resourceType == "datadog_dashboard_v2" {
			fields = dashboardmapping.FieldSpecsToSDKv2Schema(dashboardmapping.DashboardTopLevelFields)
			fields["id"] = &schema.Schema{Computed: true}
			fields["widget"] = &schema.Schema{Type: schema.TypeList, Elem: &schema.Resource{Schema: dashboardmapping.AllWidgetSDKv2Schema(false)}}
		}
		if hasUnknownWithSchema(change.Change.AfterUnknown, fields) {
			return planResource{}, fmt.Errorf("resource %q contains unknown planned dashboard values", address)
		}
	}
	return resource, nil
}

// Computed dashboard/widget metadata can be unknown on create. Configured
// widget URLs and other behavior must be known; the official schema decides
// which nested ID/URL fields are computed, including supported group widgets.
func hasUnknownWithSchema(value interface{}, fields map[string]*schema.Schema) bool {
	switch typed := value.(type) {
	case map[string]interface{}:
		for key, child := range typed {
			field := fields[key]
			if field != nil && field.Computed && (key == "id" || key == "url" || key == "dashboard_lists_removed") {
				continue
			}
			var nested map[string]*schema.Schema
			if field != nil {
				if resource, ok := field.Elem.(*schema.Resource); ok {
					nested = resource.Schema
				}
			}
			if hasUnknownWithSchema(child, nested) {
				return true
			}
		}
	case []interface{}:
		for _, child := range typed {
			if hasUnknownWithSchema(child, fields) {
				return true
			}
		}
	case bool:
		return typed
	}
	return false
}

// A null optional numeric field is absent, whereas an explicit zero must remain.
// Removing null map entries lets the official mapping preserve that distinction.
func omitNulls(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(typed))
		for key, child := range typed {
			if child != nil {
				result[key] = omitNulls(child)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(typed))
		for i, child := range typed {
			result[i] = omitNulls(child)
		}
		return result
	default:
		return value
	}
}

func removeMetadata(dashboard map[string]interface{}) {
	delete(dashboard, "id")
	delete(dashboard, "url")
	var cleanWidgets func(interface{})
	cleanWidgets = func(raw interface{}) {
		widgets, _ := raw.([]interface{})
		for _, rawWidget := range widgets {
			widget, _ := rawWidget.(map[string]interface{})
			delete(widget, "id")
			if definition, ok := widget["definition"].(map[string]interface{}); ok {
				delete(definition, "id")
				cleanWidgets(definition["widgets"])
			}
		}
	}
	cleanWidgets(dashboard["widgets"])
}
