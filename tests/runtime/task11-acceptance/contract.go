// Development-only acceptance controller. Never linked into the shipping CLI.
package main

import (
	"errors"
	"strings"
)

const (
	incoming = "/var/cache/cloud-8021x/artifacts"
	control  = "/var/lib/cloud8021x-task11/control"
	helper   = "/usr/local/libexec/task11-acceptance"
	marker   = "/etc/cloud8021x-task11-fixture"
)

var nodes = []string{"blue-primary", "blue-secondary", "green-primary", "green-secondary"}

type step struct{ Node, Operation string }

func stagePlan(stage string) ([]step, error) {
	capture := []step{{"blue-primary", "capture"}, {"blue-primary", "transfer"}, {"green-primary", "prepare"}, {"blue-secondary", "capture"}, {"blue-secondary", "transfer"}, {"green-secondary", "prepare"}}
	switch stage {
	case "keys":
		return []step{{"blue-primary", "source-key"}, {"blue-secondary", "source-key"}, {"green-primary", "source-key"}, {"green-secondary", "source-key"}}, nil
	case "prepare":
		return capture, nil
	case "cutover":
		return append(capture, step{"green-primary", "activate"}, step{"green-secondary", "activate"}, step{"green-primary", "activate"}), nil
	case "deactivate":
		return []step{{"green-primary", "deactivate"}, {"green-secondary", "deactivate"}}, nil
	case "proofs":
		return []step{{"green-primary", "rollback-proof"}, {"green-secondary", "rollback-proof"}, {"green-primary", "reverse-transfer"}, {"green-secondary", "reverse-transfer"}}, nil
	case "observe", "recover", "verify-cloud":
		return []step{{"green-primary", stage}}, nil
	case "resume":
		return []step{{"blue-primary", "resume-source"}, {"blue-secondary", "resume-source"}}, nil
	default:
		return nil, errors.New("choose one explicit acceptance stage")
	}
}
func shippingCommand(op string) ([]string, error) {
	switch op {
	case "source-key", "capture", "prepare", "resume-source":
		return []string{incoming + "/cloud-8021x", "bootstrap", op, "--incoming"}, nil
	case "activate", "deactivate", "rollback-proof":
		return []string{"/usr/local/bin/cloud-8021x", "--config", "/etc/cloud-8021x/config.yaml", "bootstrap", op}, nil
	default:
		return nil, errors.New("operation is not an allowlisted shipping bootstrap command")
	}
}
func receiptPaths(kind, role string) (string, string, error) {
	if (kind != "parallel" && kind != "rollback") || (role != "radius-primary" && role != "radius-secondary") {
		return "", "", errors.New("unknown protected receipt slot")
	}
	name := kind + "-" + role + ".json"
	return "/var/lib/cloud-8021x-bootstrap/" + name, incoming + "/" + name, nil
}
func roleOf(node string) string {
	if strings.HasSuffix(node, "-secondary") {
		return "radius-secondary"
	}
	return "radius-primary"
}
