package main

import (
	"encoding/base64"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type secretVersion struct {
	Data  string `json:"data"`
	State string `json:"state"`
}

func (f *fixture) secretManager(r *http.Request, body []byte) (int, any) {
	resource := strings.TrimPrefix(r.URL.Path, "/v1/")
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		return 404, map[string]string{"error": "unlisted secret path"}
	}
	if r.Method == "POST" && strings.HasSuffix(resource, ":addVersion") && r.URL.RawQuery == "" {
		name := f.canonical(strings.TrimSuffix(resource, ":addVersion"))
		suffix := strings.TrimPrefix(name, "projects/"+f.config.ProjectNumber+"/secrets/")
		versions := f.remote.Secrets[name]
		if versions == nil || (suffix != "radius-smallstep-server-cert" && suffix != "radius-smallstep-server-key") {
			return 404, map[string]string{"error": "publication resource not allowed"}
		}
		if f.phase != "active" {
			return 403, map[string]string{"error": "passive publication denied"}
		}
		var request struct {
			Payload struct {
				Data string `json:"data"`
				CRC  string `json:"dataCrc32c"`
			} `json:"payload"`
		}
		if strictJSON(body, &request) != nil {
			return 400, map[string]string{"error": "invalid publication"}
		}
		data, err := base64.StdEncoding.DecodeString(request.Payload.Data)
		if err != nil || len(data) == 0 || len(data) > 1<<20 || request.Payload.CRC != crcString(data) {
			return 400, map[string]string{"error": "invalid publication payload or CRC"}
		}
		if len(versions) >= 100 {
			return 429, map[string]string{"error": "version bound reached"}
		}
		var highest uint64
		for version := range versions {
			n, _ := strconv.ParseUint(version, 10, 64)
			if n > highest {
				highest = n
			}
		}
		if highest == ^uint64(0) {
			return 409, map[string]string{"error": "version exhausted"}
		}
		version := strconv.FormatUint(highest+1, 10)
		versions[version] = secretVersion{Data: request.Payload.Data, State: "ENABLED"}
		return 200, map[string]string{"name": name + "/versions/" + version, "state": "ENABLED"}
	}
	if r.Method == "GET" && strings.HasSuffix(resource, "/versions") && r.URL.Query().Encode() == "filter=state%3DENABLED&pageSize=100" {
		name := f.canonical(strings.TrimSuffix(resource, "/versions"))
		versions := f.remote.Secrets[name]
		if versions != nil {
			numbers := []uint64{}
			for version, item := range versions {
				if item.State == "ENABLED" {
					n, _ := strconv.ParseUint(version, 10, 64)
					numbers = append(numbers, n)
				}
			}
			sort.Slice(numbers, func(i, j int) bool { return numbers[i] > numbers[j] })
			out := []map[string]string{}
			for _, n := range numbers {
				out = append(out, map[string]string{"name": name + "/versions/" + strconv.FormatUint(n, 10), "state": "ENABLED"})
			}
			return 200, map[string]any{"versions": out}
		}
	}
	if r.Method == "GET" && strings.HasSuffix(resource, ":access") && r.URL.RawQuery == "" {
		name := strings.TrimSuffix(resource, ":access")
		base, version, ok := strings.Cut(name, "/versions/")
		item, exists := f.remote.Secrets[f.canonical(base)][version]
		if ok && exists && item.State == "ENABLED" {
			data, err := base64.StdEncoding.DecodeString(item.Data)
			if err == nil {
				return 200, map[string]any{"name": f.canonical(name), "payload": map[string]string{"data": item.Data, "dataCrc32c": crcString(data)}}
			}
		}
	}
	return 404, map[string]string{"error": "unlisted secret request"}
}
