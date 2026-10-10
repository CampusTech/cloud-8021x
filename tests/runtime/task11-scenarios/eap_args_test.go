package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestFixedEAPArgumentsFreezeSourceStationAndPrivateInputs(t *testing.T) {
	p := pureNASPlan()
	secret := []byte("task11-private-nas-secret")
	p.Materials["radius-secret"] = digestBytes(secret)
	actual, e := fixedEAPArguments(p, secret)
	if e != nil {
		t.Fatal(e)
	}
	wanted := []string{"-c", nasMaterialRoot + "/eap.conf", "-a", "10.203.11.40", "-A", "10.203.11.40", "-p", "18120", "-s", string(secret), "-M", p.Station, "-t", "15", "-N", "61:d:19"}
	if !reflect.DeepEqual(actual, wanted) {
		t.Fatal("independent station/source or fixed peer invocation changed")
	}
	for _, name := range []string{"station", "nas", "secret-pin", "secret-lines", "secret-origin"} {
		t.Run(name, func(t *testing.T) {
			plan := pureNASPlan()
			plan.Materials["radius-secret"] = digestBytes(secret)
			value := append([]byte(nil), secret...)
			switch name {
			case "station":
				plan.Station = "unknown"
			case "nas":
				plan.Scenario.NAS = "127.0.0.1"
			case "secret-pin":
				plan.Materials["radius-secret"] = strings.Repeat("a", 64)
			case "secret-lines":
				value = append(value, '\n')
				plan.Materials["radius-secret"] = digestBytes(value)
			case "secret-origin":
				value = []byte("production-private-nas-secret")
				plan.Materials["radius-secret"] = digestBytes(value)
			}
			if _, e := fixedEAPArguments(plan, value); e == nil {
				t.Fatal("unsafe/unpinned EAP private input accepted")
			}
		})
	}
}
