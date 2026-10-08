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
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func syncCommand() *cobra.Command {
	var root string
	var check, dryRun, debug bool
	command := &cobra.Command{Use: "sync", Short: "Synchronize both dashboard exports and the native HCL companion in an isolated planner", Args: cobra.NoArgs, SilenceUsage: true}
	command.Flags().StringVar(&root, "root", "../..", "Repository root containing dashboard HCL")
	command.Flags().BoolVar(&check, "check", false, "Check all generated artifacts without changing files")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "Report changes without writing files")
	command.Flags().BoolVar(&debug, "debug", false, "Enable debug logging")
	command.RunE = func(cmd *cobra.Command, _ []string) error {
		return syncDashboards(cmd.ErrOrStderr(), root, check, dryRun, debug)
	}
	return command
}

type localExpression struct {
	source     []byte
	expression hcl.Expression
}

// Only the transitive dashboard-local expressions are copied. No Terraform
// backend, resource, provider, tfvars, or state is read from the real module.
func isolatedDashboardConfig(root string) ([]byte, error) {
	files, err := filepath.Glob(filepath.Join(root, "datadog*.tf"))
	if err != nil {
		return nil, err
	}
	locals := map[string]localExpression{}
	for _, path := range files {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		file, diags := hclsyntax.ParseConfig(content, path, hcl.InitialPos)
		if diags.HasErrors() {
			return nil, fmt.Errorf("parse dashboard source: %s", diags.Error())
		}
		for _, block := range file.Body.(*hclsyntax.Body).Blocks {
			if block.Type != "locals" {
				continue
			}
			for name, attribute := range block.Body.Attributes {
				if _, exists := locals[name]; exists {
					return nil, fmt.Errorf("duplicate dashboard local %q", name)
				}
				locals[name] = localExpression{source: content, expression: attribute.Expr}
			}
		}
	}
	var visit func(string) error
	selected := map[string]string{}
	visiting := map[string]bool{}
	stubs := map[string]string{
		"local.datadog_radius_hosts":                    `{ "radius-primary" = "radius-primary", "radius-secondary" = "radius-secondary" }`,
		"var.datadog_app_key":                           `"offline-dashboard-export"`,
		"var.enable_smallstep_ca":                       "true",
		"var.enable_radius_usage_collector":             "false",
		"var.radius_usage_preview_id":                   `""`,
		"var.datadog_usage_sites":                       "{}",
		"google_compute_instance.radius.name":           `"radius-primary"`,
		"google_compute_instance.radius_secondary.name": `"radius-secondary"`,
	}
	visit = func(name string) error {
		if _, done := selected[name]; done {
			return nil
		}
		if visiting[name] {
			return fmt.Errorf("cyclic dashboard local %q", name)
		}
		local, ok := locals[name]
		if !ok {
			return fmt.Errorf("missing dashboard local %q", name)
		}
		// Walk parsed calls, rather than searching strings that might contain
		// ordinary documentation or URLs. Absolute file paths would otherwise
		// escape the temporary Terraform module's isolation.
		diagnostics := hclsyntax.VisitAll(local.expression.(hclsyntax.Expression), func(node hclsyntax.Node) hcl.Diagnostics {
			call, ok := node.(*hclsyntax.FunctionCallExpr)
			if !ok {
				return nil
			}
			switch call.Name {
			case "file", "filebase64", "fileexists", "fileset", "templatefile", "filemd5", "filesha1", "filesha256", "filesha512", "filebase64sha256", "filebase64sha512":
				return hcl.Diagnostics{&hcl.Diagnostic{Severity: hcl.DiagError, Summary: "filesystem functions are prohibited in isolated dashboard locals", Detail: fmt.Sprintf("local %q calls %q", name, call.Name)}}
			}
			return nil
		})
		if diagnostics.HasErrors() {
			return diagnostics
		}
		visiting[name] = true
		rangeExpr := local.expression.Range()
		expression := string(local.source[rangeExpr.Start.Byte:rangeExpr.End.Byte])
		type replacement struct {
			start, end int
			text       string
		}
		var replacements []replacement
		for _, traversal := range local.expression.Variables() {
			var names []string
			for _, step := range traversal {
				switch typed := step.(type) {
				case hcl.TraverseRoot:
					names = append(names, typed.Name)
				case hcl.TraverseAttr:
					names = append(names, typed.Name)
				case hcl.TraverseIndex:
					// Constant map indexes do not add a dependency name.
				}
			}
			path := strings.Join(names, ".")
			stubTraversal := traversal
			if len(names) >= 2 && (names[0] == "local" || names[0] == "var") {
				prefix := strings.Join(names[:2], ".")
				if _, ok := stubs[prefix]; ok {
					path = prefix
					stubTraversal = traversal[:2]
				}
			}
			if stub, ok := stubs[path]; ok {
				r := stubTraversal.SourceRange()
				replacements = append(replacements, replacement{r.Start.Byte - rangeExpr.Start.Byte, r.End.Byte - rangeExpr.Start.Byte, stub})
				continue
			}
			if len(names) >= 2 && names[0] == "local" {
				if err := visit(names[1]); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("dashboard local %q references unsupported dependency %q", name, path)
		}
		sort.Slice(replacements, func(i, j int) bool { return replacements[i].start > replacements[j].start })
		for _, r := range replacements {
			expression = expression[:r.start] + r.text + expression[r.end:]
		}
		selected[name] = expression
		delete(visiting, name)
		return nil
	}
	for _, name := range []string{"dashboard_json", "smallstep_dashboard_json"} {
		if err := visit(name); err != nil {
			return nil, err
		}
	}
	var config bytes.Buffer
	config.WriteString("locals {\n")
	keys := make([]string, 0, len(selected))
	for name := range selected {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		fmt.Fprintf(&config, "  %s = %s\n", name, selected[name])
	}
	config.WriteString("}\noutput \"radius\" { value = jsonencode(local.dashboard_json) }\noutput \"smallstep\" { value = jsonencode(local.smallstep_dashboard_json) }\n")
	return config.Bytes(), nil
}

func syncDashboards(stderr io.Writer, root string, check, dryRun, debug bool) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	config, err := isolatedDashboardConfig(root)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "dashboard-sync-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.WriteFile(filepath.Join(dir, "dashboard.tf"), config, 0600); err != nil {
		return err
	}
	cliConfig := filepath.Join(dir, "terraform.rc")
	if err := os.WriteFile(cliConfig, nil, 0600); err != nil {
		return err
	}
	terraform, err := exec.LookPath("terraform")
	if err != nil {
		return fmt.Errorf("terraform is required for sync: %w", err)
	}
	logger := logrus.New()
	logger.SetOutput(stderr)
	if debug {
		logger.SetLevel(logrus.DebugLevel)
	}
	var env []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "TF_") && !strings.HasPrefix(entry, "CHECKPOINT_DISABLE=") {
			env = append(env, entry)
		}
	}
	env = append(env, "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1", "TF_CLI_CONFIG_FILE="+cliConfig)
	run := func(args ...string) ([]byte, error) {
		logger.WithField("operation", args[0]).Debug("evaluating dashboards in isolated Terraform directory")
		command := exec.Command(terraform, args...)
		command.Dir = dir
		command.Env = env
		result, err := command.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("isolated terraform %s: %w\n%s", args[0], err, result)
		}
		return result, nil
	}
	if _, err := run("init", "-backend=false", "-input=false", "-no-color"); err != nil {
		return err
	}
	if _, err := run("plan", "-refresh=false", "-input=false", "-no-color", "-out=dashboard.plan"); err != nil {
		return err
	}
	planJSON, err := run("show", "-json", "dashboard.plan")
	if err != nil {
		return err
	}
	var plan struct {
		PlannedValues struct {
			Outputs map[string]struct {
				Value string `json:"value"`
			} `json:"outputs"`
		} `json:"planned_values"`
	}
	if err := decodeJSON(planJSON, &plan); err != nil {
		return fmt.Errorf("decode isolated plan: %w", err)
	}
	var radius map[string]interface{}
	if err := decodeJSON([]byte(plan.PlannedValues.Outputs["radius"].Value), &radius); err != nil {
		return fmt.Errorf("decode planned radius output: %w", err)
	}
	companion, losses, err := buildCompanion(radius)
	if err != nil {
		return err
	}
	artifacts := map[string][]byte{
		"docs/generated/datadog-dashboard-v2.tf":          companion,
		"docs/generated/datadog-dashboard-v2-losses.json": losses,
	}
	for name, output := range map[string]string{"radius": "datadog-dashboard.json", "smallstep": "datadog-smallstep-dashboard.json"} {
		var dashboard map[string]interface{}
		if err := decodeJSON([]byte(plan.PlannedValues.Outputs[name].Value), &dashboard); err != nil {
			return fmt.Errorf("decode planned %s output: %w", name, err)
		}
		content, err := json.MarshalIndent(dashboard, "", "  ")
		if err != nil {
			return err
		}
		artifacts[output] = append(content, '\n')
	}
	paths := make([]string, 0, len(artifacts))
	for path := range artifacts {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var drift []string
	for _, path := range paths {
		content := artifacts[path]
		fullPath := filepath.Join(root, path)
		current, err := os.ReadFile(fullPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		matches := bytes.Equal(current, content)
		if strings.HasSuffix(path, ".json") && err == nil {
			var expected, actual interface{}
			if decodeJSON(current, &actual) == nil && decodeJSON(content, &expected) == nil {
				matches = reflect.DeepEqual(expected, actual)
			}
		}
		if matches {
			continue
		}
		drift = append(drift, path)
		if check || dryRun {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(fullPath, content, 0644); err != nil {
			return err
		}
	}
	if check && len(drift) > 0 {
		return fmt.Errorf("dashboard artifacts differ from source: %s", strings.Join(drift, ", "))
	}
	logger.WithFields(logrus.Fields{"changed_files": drift, "check": check, "dry_run": dryRun}).Info("dashboard artifacts synchronized")
	return nil
}
