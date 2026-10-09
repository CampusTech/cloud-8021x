package main

import "encoding/json"

func beginAttempt(path, stage, sha string) error {
	b, _ := json.Marshal(struct {
		Stage string `json:"stage"`
		SHA   string `json:"plan_sha256"`
	}{stage, sha})
	return publish(path, append(b, '\n'), 0600)
}
