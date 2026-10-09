package main

import "errors"

func stageOrder(stage string) ([]string, error) {
	switch stage {
	case "assemble":
		return []string{"preflight", "lower", "private-roots", "network", "units", "inventory"}, nil
	case "start-primitive":
		return []string{"start-primitive"}, nil
	case "start-original":
		return []string{"verify-primitive", "stop-primitive", "start-installed-api", "initialize-postgres", "start-nodes", "migrate-blue", "start-blue-services"}, nil
	default:
		return nil, errors.New("unknown fixed stage")
	}
}
