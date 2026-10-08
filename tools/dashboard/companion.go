package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/terraform-providers/terraform-provider-datadog/datadog/dashboardmapping"
	"github.com/zclconf/go-cty/cty"
)

const nativeProviderDependency = "https://github.com/DataDog/terraform-provider-datadog/pull/4225"

type companionLoss struct {
	Path   string      `json:"path"`
	Source interface{} `json:"source"`
	Reason string      `json:"reason"`
}

type companionLossReport struct {
	ProviderVersion   string          `json:"provider_version"`
	DeploymentBlocked bool            `json:"deployment_blocked"`
	Dependency        string          `json:"upstream_dependency"`
	Losses            []companionLoss `json:"losses"`
	Normalizations    []companionLoss `json:"normalizations"`
}

// buildCompanion uses the released provider's own flattening and schema, rather
// than maintaining a second handwritten translation of dashboard properties.
// The generated native resource stays outside the root module and has count=0:
// it is a review artifact while the released provider cannot retain all fields.
func buildCompanion(radius map[string]interface{}) ([]byte, []byte, error) {
	apiWidgets, ok := radius["widgets"].([]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("native companion requires a known widget list")
	}
	flattened, drops := dashboardmapping.FlattenWidgetsForSDKv2(apiWidgets)
	if len(drops) != 0 {
		return nil, nil, fmt.Errorf("unrecognized provider flatten losses: %v", drops)
	}
	values := dashboardmapping.FlattenEngineJSON(dashboardmapping.DashboardTopLevelFields, radius)
	values["widget"] = flattened
	if variables, ok := radius["template_variables"].([]interface{}); ok {
		values["template_variable"] = dashboardmapping.FlattenTemplateVariables(variables)
	}
	// Read flatten helpers can return []string, while the SDK map builder expects
	// Terraform-decoded []interface{}. Normalize the container representation.
	flattenedJSON, err := json.Marshal(values)
	if err != nil {
		return nil, nil, fmt.Errorf("encode flattened native values: %w", err)
	}
	if err := json.Unmarshal(flattenedJSON, &values); err != nil {
		return nil, nil, fmt.Errorf("decode flattened native values: %w", err)
	}
	projected := dashboardmapping.BuildDashboardEngineJSONFromMap(values, "")
	// Normalize Go numeric representations before comparing API JSON values.
	serialized, err := json.Marshal(projected)
	if err != nil {
		return nil, nil, fmt.Errorf("encode native projection: %w", err)
	}
	if err := json.Unmarshal(serialized, &projected); err != nil {
		return nil, nil, fmt.Errorf("decode native projection: %w", err)
	}
	report := companionLossReport{
		ProviderVersion: "4.25.0", DeploymentBlocked: true,
		Dependency: nativeProviderDependency,
		Losses:     []companionLoss{}, Normalizations: []companionLoss{},
	}
	if err := compareCompanion(radius, projected, "$", "", "", &report); err != nil {
		return nil, nil, err
	}
	nativeSchema := dashboardmapping.FieldSpecsToSDKv2Schema(dashboardmapping.DashboardTopLevelFields)
	nativeSchema["widget"] = &schema.Schema{Type: schema.TypeList, Elem: &schema.Resource{
		Schema: dashboardmapping.AllWidgetSDKv2Schema(false),
	}}
	file := hclwrite.NewEmptyFile()
	resource := file.Body().AppendNewBlock("resource", []string{"datadog_dashboard_v2", "radius_native_companion"})
	resource.Body().SetAttributeValue("count", cty.NumberIntVal(0))
	if err := writeCompanionFields(resource.Body(), values, nativeSchema, "$native"); err != nil {
		return nil, nil, err
	}
	var heading strings.Builder
	heading.WriteString("# GENERATED FILE: regenerate with tools/dashboard sync; do not edit.\n")
	heading.WriteString("# DO NOT APPLY: this is a native HCL companion, not a roundtrip-equivalent dashboard.\n")
	heading.WriteString("# The root module intentionally retains datadog_dashboard_json.radius.\n")
	heading.WriteString("# This resource is disabled (count = 0); released provider 4.25.0 loses the options below.\n")
	heading.WriteString("# Native migration depends on " + nativeProviderDependency + " being released and verified.\n")
	for _, loss := range report.Losses {
		value, _ := json.Marshal(loss.Source)
		fmt.Fprintf(&heading, "# Unsupported: %s = %s (%s)\n", loss.Path, value, loss.Reason)
	}
	for _, normalization := range report.Normalizations {
		fmt.Fprintf(&heading, "# Provider serialization: %s (%s)\n", normalization.Path, normalization.Reason)
	}
	hclBytes := append([]byte(heading.String()+"\n"), file.Bytes()...)
	lossJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("encode companion loss report: %w", err)
	}
	return hclBytes, append(lossJSON, '\n'), nil
}

// Only these current, understood discrepancies are permitted. A newly added
// unsupported option or a changed query/column/formula stops artifact generation.
func compareCompanion(source, projected interface{}, path, widgetType, dataSource string, report *companionLossReport) error {
	switch value := source.(type) {
	case map[string]interface{}:
		other, ok := projected.(map[string]interface{})
		if !ok {
			return fmt.Errorf("unrecognized native roundtrip loss at %s", path)
		}
		if kind, ok := value["type"].(string); ok && strings.HasSuffix(path, ".definition") {
			widgetType = kind
		}
		if source, ok := value["data_source"].(string); ok {
			dataSource = source
		}
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			childPath := path + "." + key
			actual, exists := other[key]
			if !exists {
				switch {
				case key == "should_exclude_missing" && value[key] == false && dataSource == "logs" && strings.Contains(path, ".queries[") && strings.Contains(path, ".group_by["):
					report.Losses = append(report.Losses, companionLoss{Path: childPath, Source: false,
						Reason: "native logs group_by schema cannot express missing-bucket inclusion"})
					continue
				case key == "hide_total" && widgetType == "sunburst" && value[key] == false && strings.HasSuffix(path, ".definition"):
					report.Normalizations = append(report.Normalizations, companionLoss{Path: childPath, Source: false,
						Reason: "modeled false is retained in HCL but omitted by provider JSON serialization"})
					continue
				case key == "available_values" && strings.HasPrefix(path, "$.template_variables["):
					if choices, ok := value[key].([]interface{}); ok && len(choices) == 0 {
						report.Normalizations = append(report.Normalizations, companionLoss{Path: childPath, Source: choices,
							Reason: "empty variable choices are retained in HCL but omitted by provider JSON serialization"})
						continue
					}
				}
			}
			if err := compareCompanion(value[key], actual, childPath, widgetType, dataSource, report); err != nil {
				return err
			}
		}
	case []interface{}:
		other, ok := projected.([]interface{})
		if !ok || len(value) != len(other) {
			return fmt.Errorf("unrecognized native roundtrip loss at %s", path)
		}
		for index, child := range value {
			if err := compareCompanion(child, other[index], fmt.Sprintf("%s[%d]", path, index), widgetType, dataSource, report); err != nil {
				return err
			}
		}
	default:
		if !reflect.DeepEqual(source, projected) {
			return fmt.Errorf("unrecognized native roundtrip loss at %s: source=%v native=%v", path, source, projected)
		}
	}
	return nil
}

func writeCompanionFields(body *hclwrite.Body, values map[string]interface{}, fields map[string]*schema.Schema, path string) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		field, ok := fields[key]
		if !ok {
			return fmt.Errorf("unmodeled native HCL field %s.%s", path, key)
		}
		if field.Computed && !field.Optional || values[key] == nil {
			continue
		}
		if nested, ok := field.Elem.(*schema.Resource); ok {
			items, ok := values[key].([]interface{})
			if !ok {
				return fmt.Errorf("invalid native block list %s.%s", path, key)
			}
			for index, item := range items {
				object, ok := item.(map[string]interface{})
				if !ok {
					return fmt.Errorf("invalid native block %s.%s[%d]", path, key, index)
				}
				block := body.AppendNewBlock(key, nil)
				if err := writeCompanionFields(block.Body(), object, nested.Schema, fmt.Sprintf("%s.%s[%d]", path, key, index)); err != nil {
					return err
				}
			}
			continue
		}
		value, err := companionAttribute(values[key])
		if err != nil {
			return fmt.Errorf("encode native attribute %s.%s: %w", path, key, err)
		}
		body.SetAttributeValue(key, value)
	}
	return nil
}

func companionAttribute(value interface{}) (cty.Value, error) {
	switch value := value.(type) {
	case string:
		return cty.StringVal(value), nil
	case bool:
		return cty.BoolVal(value), nil
	case int:
		return cty.NumberIntVal(int64(value)), nil
	case int64:
		return cty.NumberIntVal(value), nil
	case float64:
		return cty.NumberFloatVal(value), nil
	case []string:
		items := make([]cty.Value, len(value))
		for i, item := range value {
			items[i] = cty.StringVal(item)
		}
		return cty.TupleVal(items), nil
	case []int:
		items := make([]cty.Value, len(value))
		for i, item := range value {
			items[i] = cty.NumberIntVal(int64(item))
		}
		return cty.TupleVal(items), nil
	case []interface{}:
		items := make([]cty.Value, len(value))
		for i, item := range value {
			var err error
			items[i], err = companionAttribute(item)
			if err != nil {
				return cty.NilVal, err
			}
		}
		return cty.TupleVal(items), nil
	default:
		return cty.NilVal, fmt.Errorf("unsupported attribute value %T", value)
	}
}
