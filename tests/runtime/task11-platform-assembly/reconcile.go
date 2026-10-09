package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

func (o operation) reconcile(_ string) error {
	expected := makeInventory(o.in, o.planSHA)
	encoded, _ := json.Marshal(expected)
	raw, e := readPinned(controlRoot+"/platform-inventory.json", digest(encoded), 1<<20, true)
	if e != nil {
		return e
	}
	var actual inventory
	if domain.DecodeJSONStrict(raw, &actual) != nil || !sameJSON(actual, expected) {
		return errors.New("current plan and installed inventory differ")
	}
	mounts, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil || len(mounts) > 4<<20 {
		return errors.New("actual owned mount inventory unavailable")
	}
	for _, n := range o.in.Plan.Nodes {
		if !strings.Contains(string(mounts), " "+rootFor(n.Name)+" ") {
			return errors.New("actual node overlay absent")
		}
	}
	for _, ep := range endpoints(o.in.Plan) {
		b, e := o.r.call(o.ctx, "ip", "-j", "-n", ep.Name, "address", "show", "dev", "eth0")
		if e != nil {
			return e
		}
		var records []struct {
			IfName   string                           `json:"ifname"`
			AddrInfo []struct{ Family, Local string } `json:"addr_info"`
		}
		if json.Unmarshal(b, &records) != nil || len(records) != 1 || records[0].IfName != "eth0" || len(records[0].AddrInfo) != 1 || records[0].AddrInfo[0].Family != "inet" || records[0].AddrInfo[0].Local != ep.Address {
			return errors.New("actual fixed namespace address differs")
		}
		b, e = o.r.call(o.ctx, "ip", "-n", ep.Name, "route", "show", "default")
		if e != nil || len(strings.TrimSpace(string(b))) != 0 {
			return errors.New("namespace default route refused")
		}
	}
	return nil
}
