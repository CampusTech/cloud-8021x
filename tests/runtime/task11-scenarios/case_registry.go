package main

import "errors"

// Only these reviewed case filenames may be selected under the fixed protected
// plans directory. No environment, pathname or generic command override exists.
func closedCaseFiles(command string) ([]string, error) {
	switch command {
	case "eap-unenrolled":
		return []string{"eap-unenrolled.json"}, nil
	case "native-accounting":
		return []string{"native-accounting.json"}, nil
	case "ongoing-baseline":
		return []string{"ongoing-interim.json", "ongoing-stop.json"}, nil
	case "duplicate-pair":
		return []string{"duplicate-pair.json"}, nil
	case "ha-primary":
		return []string{"ha-primary.json"}, nil
	case "postgres-outage":
		return []string{"postgres-outage.json"}, nil
	case "business-outage":
		return []string{"business-outage.json"}, nil
	case "ca-continuity":
		return []string{"ca-ec-continuity.json", "ca-rsa-continuity.json"}, nil
	default:
		return nil, errors.New("unknown closed scenario case")
	}
}
func validateOuterCAPhase(command, phase string) error {
	if _, err := closedCaseFiles(command); err != nil {
		return err
	}
	if command != "ca-continuity" {
		if phase != "" {
			return errors.New("CA phase outside CA continuity case")
		}
		return nil
	}
	switch phase {
	case "original", "adopted", "passive":
		return nil
	default:
		return errors.New("explicit closed CA phase required")
	}
}
