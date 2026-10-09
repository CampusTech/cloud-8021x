// task11-platform-assembly is a development fixture installer. It has no shipping role.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	seed "github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type inventoryNode struct {
	Name         string `json:"name"`
	Machine      string `json:"machine"`
	Root         string `json:"root"`
	Namespace    string `json:"namespace"`
	Address      string `json:"address"`
	MachineID    string `json:"machine_id"`
	ConfigSHA256 string `json:"config_sha256"`
}
type inventoryAux struct {
	Name      string `json:"name"`
	Root      string `json:"root"`
	Namespace string `json:"namespace"`
	Address   string `json:"address"`
}
type inventory struct {
	Schema          int             `json:"schema"`
	PlanSHA256      string          `json:"plan_sha256"`
	InputSHA256     string          `json:"input_sha256"`
	CandidateSHA256 string          `json:"candidate_sha256"`
	Nodes           []inventoryNode `json:"nodes"`
	Auxiliary       []inventoryAux  `json:"auxiliary"`
	Helpers         map[string]pin  `json:"helpers"`
}

func makeInventory(in inputs, sha string) inventory {
	v := inventory{Schema: 1, PlanSHA256: sha, InputSHA256: in.Plan.InputSHA256, CandidateSHA256: in.Plan.CandidateSHA256, Helpers: map[string]pin{}}
	for _, n := range in.Plan.Nodes {
		v.Nodes = append(v.Nodes, inventoryNode{n.Name, "task11-" + n.Name, rootFor(n.Name), n.Namespace, n.Address, n.MachineID, digest(in.Files[n.Name+"/var/cache/cloud-8021x/artifacts/config.yaml"])})
	}
	for _, a := range []struct{ n, ip string }{{"api", "10.203.11.10"}, {"pg", "10.203.11.11"}, {"nas", "10.203.11.40"}} {
		v.Auxiliary = append(v.Auxiliary, inventoryAux{a.n, platformRoot + "/aux/" + a.n, "c11-" + a.n, a.ip})
	}
	for k, p := range in.Plan.Helpers {
		v.Helpers[k] = pin{"/usr/local/libexec/" + k, p.SHA256}
	}
	return v
}
func (o operation) inventory() error {
	if e := o.capacityAfterAssembly(); e != nil {
		return e
	}
	v := makeInventory(o.in, o.planSHA)
	// Inventory binds exact independently pinned input bytes, never readiness.
	raw, _ := json.Marshal(v)
	return publish(controlRoot+"/platform-inventory.json", raw, 0600)
}
func command() *cobra.Command {
	var sha, result string
	var dry, debug bool
	cmd := &cobra.Command{Use: "task11-platform-assembly assemble|start-primitive|start-original|audit-loops", Args: cobra.ExactArgs(1), SilenceUsage: true, SilenceErrors: true, RunE: func(cmd *cobra.Command, args []string) error {
		stage := args[0]
		if stage != "audit-loops" {
			if _, e := stageOrder(stage); e != nil {
				return e
			}
		}
		if !seed.IsSHA(sha) || (stage == "start-original" && !seed.IsSHA(result)) || (stage != "start-original" && result != "") {
			return errors.New("independently pinned fixed plan and applicable primitive result required")
		}
		if e := observePlatform(stage != "assemble"); e != nil {
			return e
		}
		raw, e := readPinned(controlRoot+"/platform-plan.json", sha, 1<<20, true)
		if e != nil {
			return e
		}
		var p plan
		if domain.DecodeJSONStrict(raw, &p) != nil {
			return errors.New("strict platform plan required")
		}
		in, e := loadInputs(p)
		if e != nil {
			return e
		}
		if debug {
			logrus.WithFields(logrus.Fields{"operation": stage, "dry_run": dry, "nodes": len(p.Nodes)}).Info("development platform input validation")
		}
		if dry {
			return nil
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Minute)
		defer cancel()
		op := operation{in: in, r: runner{p}, ctx: ctx, planSHA: sha}
		if stage == "audit-loops" {
			return op.auditLoops()
		}
		if stage != "assemble" {
			if e = op.reconcile(sha); e != nil {
				return e
			}
		}
		return op.run(stage, sha, result)
	}}
	cmd.Flags().StringVar(&sha, "plan-sha256", "", "Independent SHA256 of fixed root-private platform-plan.json")
	cmd.Flags().StringVar(&result, "primitive-result-sha256", "", "Independent SHA256 of actual primitive verified-result.json; start-original only")
	cmd.Flags().BoolVar(&dry, "dry-run", false, "Validate protected inputs without processes, connections or writes")
	cmd.Flags().BoolVar(&debug, "debug", false, "Log only public operation and input counts")
	return cmd
}
func main() {
	if command().Execute() != nil {
		logrus.WithField("component", "task11-platform-assembly").Error("development platform operation refused; inspect protected attempt evidence")
		os.Exit(1)
	}
}
