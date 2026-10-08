// Package telemetry owns vendor-neutral application signals and durable business
// event projection. Neither trace sampling nor remote telemetry determines policy.
package telemetry

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

type BusinessRecord struct {
	ID, Category, Host string
	Received           time.Time
	Fields             map[string]any
}

// Display is local cache enrichment only. Implementations must never perform I/O
// or infer identity from NAS-supplied display names.
type Display interface {
	Enrich(*BusinessRecord, string, string, *binding.Attribution)
}

func number(n uint64) json.Number { return json.Number(strconv.FormatUint(n, 10)) }
func present(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

// Project converts only known typed fields. It does not forward raw payload maps,
// errors, signed Class tokens, certificates or arbitrary incoming attributes.
func Project(c jobs.Claim, display Display) (BusinessRecord, error) {
	r := BusinessRecord{Fields: map[string]any{"device_owner": "N/A", "device_name": "N/A", "device_model": "N/A", "ap_name": "N/A", "site_name": "N/A", "vlan_name": "N/A", "device_id": "", "vlan_id": "", "identity_verified": false, "serial": "N/A", "ssid": "N/A"}}
	kind, _, ok := strings.Cut(c.ID, ":")
	if !ok {
		return r, errors.New("invalid business identity")
	}
	r.Category = kind
	var location, called string
	var identity *binding.Attribution
	switch kind {
	case "auth":
		var e auth.Event
		if json.Unmarshal(c.Payload, &e) != nil || (e.Event != "Access-Accept" && e.Event != "Access-Reject") {
			return r, errors.New("invalid auth event")
		}
		r.ID, r.Host, r.Received = e.ID, e.Host, e.Received
		r.Fields["event"] = e.Event
		r.Fields["serial"] = present(e.Serial)
		r.Fields["nas_port_types"] = strings.Join(e.NASPortTypes, ",")
		r.Fields["nas_port_type_count"] = e.NASPortTypeCount
		r.Fields["src_ip"], r.Fields["calling_station"], r.Fields["called_station"] = e.Source, e.Station, e.Called
		r.Fields["device_id"], r.Fields["device_owner"], r.Fields["device_name"], r.Fields["device_model"] = e.DeviceID, present(e.DeviceOwner), present(e.DeviceName), present(e.DeviceModel)
		r.Fields["certificate_fingerprint"], r.Fields["vlan_id"] = e.Fingerprint, e.VLANID
		r.Fields["ap_name"], r.Fields["site_name"], r.Fields["vlan_name"] = present(e.APName), present(e.SiteName), present(e.VLANName)
		r.Fields["identity_verified"] = e.DeviceID != ""
		r.Fields["reject_reason"] = safeClass(e.Reason)
		location, called = e.Location, e.Called
	case "accounting":
		var e accounting.Event
		if json.Unmarshal(c.Payload, &e) != nil {
			return r, errors.New("invalid accounting event")
		}
		names := map[string]string{"Start": "Acct-Start", "Stop": "Acct-Stop", "Interim-Update": "Acct-Update"}
		name := names[e.Status]
		if name == "" {
			return r, errors.New("invalid accounting status")
		}
		r.ID, r.Host, r.Received = e.ID, e.Host, e.Received
		r.Fields["event"] = name
		sessionFields(r.Fields, e.Key, e.Upload, e.Download, e.Duration)
		location, called, identity = e.Location, e.CalledStation, e.Identity
		r.Fields["nas_port"] = e.NASPort
	case "usage":
		var e accounting.Interval
		if json.Unmarshal(c.Payload, &e) != nil {
			return r, errors.New("invalid usage interval")
		}
		r.ID, r.Host, r.Received = e.ID, e.Host, e.Received
		r.Fields["event"], r.Fields["usage_id"] = "Acct-Usage", e.ID
		r.Fields["counter_bits"] = e.Bits
		sessionFields(r.Fields, e.Key, e.Upload, e.Download, e.Seconds)
		location, called, identity = e.Location, e.CalledStation, e.Identity
		r.Fields["nas_port"] = e.NASPort
	default:
		return r, errors.New("unknown business category")
	}
	if r.ID == "" || c.ID != kind+":"+r.ID {
		return r, errors.New("business identity mismatch")
	}
	r.Host = present(r.Host)
	if len(called) > 18 && called[17] == ':' {
		r.Fields["ssid"] = called[18:]
	}

	r.Fields["event_id"], r.Fields["location_id"], r.Fields["called_station"] = r.ID, location, called
	if identity != nil {
		r.Fields["identity_verified"], r.Fields["device_id"], r.Fields["certificate_fingerprint"] = true, string(identity.DeviceID), identity.Fingerprint
		if identity.VLAN != nil {
			r.Fields["vlan_id"] = strconv.Itoa(*identity.VLAN)
		}
	}
	if display != nil && kind != "auth" {
		display.Enrich(&r, location, called, identity)
	}
	return r, nil
}
func sessionFields(f map[string]any, k [4]string, up, down, seconds uint64) {
	f["src_ip"], f["nas_ip"], f["calling_station"], f["session_id"] = k[0], k[1], k[2], k[3]
	f["input_bytes"], f["output_bytes"], f["session_time"] = number(up), number(down), number(seconds)
}
func safeClass(s string) string {
	if len(s) == 0 || len(s) > 64 {
		return "unknown"
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return "unknown"
		}
	}
	return s
}
