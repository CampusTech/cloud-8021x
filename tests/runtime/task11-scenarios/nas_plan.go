package main

import (
	"errors"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
)

// Names are closed inputs in the independently enrolled NAS auxiliary root.
// rsa-decrypter.pem is only the public decrypter certificate; scep-client.key
// is a synthetic client key and never an authority/Cloud KMS private key.
var nasMaterialNames = []string{
	"eap.conf", "radius-secret", "class-key", "client.pem", "client.key",
	"ec-root.pem", "ec-intermediate.pem", "rsa-root.pem", "rsa-intermediate.pem",
	"rsa-decrypter.pem", "broker.crt", "broker-token", "scep-client.key",
}

var nasRejectMaterialNames = []string{"reject-eap.conf", "reject-client.pem", "reject-client.key"}

func publishedNASMaterialNames() []string {
	return append(append([]string{}, nasMaterialNames...), nasRejectMaterialNames...)
}
func producerAllMaterialPaths() map[string]string {
	paths := map[string]string{}
	for n, p := range producerMaterialPaths {
		paths[n] = p
	}
	for n, p := range producerRejectMaterialPaths {
		paths[n] = p
	}
	return paths
}

type nasPrivatePlan struct {
	RejectMaterials    map[string]string `json:"reject_materials,omitempty"`
	RejectLeafSHA256   string            `json:"reject_leaf_sha256,omitempty"`
	Schema             int               `json:"schema"`
	OriginalSeedSHA256 string            `json:"original_seed_sha256"`
	Scenario           scenarioPlan      `json:"scenario"`
	Materials          map[string]string `json:"materials"`
	EC                 ecClientPlan      `json:"ec"`
	RSA                caClientPlan      `json:"rsa"`
	ClientLeafSHA256   string            `json:"client_leaf_sha256"`
	Station            string            `json:"station"`
}

// The controller independently pins exact plan bytes and feeds them through
// private stdin after verifying its enrolled auxiliary root/helper descriptors.
// This decoder does not generate inputs, create keys or mutate original state.
func decodeNASPlan(raw []byte, pin string) (nasPrivatePlan, error) {
	var p nasPrivatePlan
	if !shaPattern.MatchString(pin) || digestBytes(raw) != pin {
		return p, errors.New("independent NAS plan pin differs")
	}
	if e := strictJSON(raw, 64<<10, &p); e != nil {
		return p, e
	}
	if p.Schema != 1 || !shaPattern.MatchString(p.OriginalSeedSHA256) || p.OriginalSeedSHA256 != p.Scenario.OriginalSeedSHA256 || !shaPattern.MatchString(p.ClientLeafSHA256) || validatePlan(p.Scenario) != nil || len(p.Materials) != len(nasMaterialNames) {
		return p, errors.New("immutable NAS identity/material plan invalid")
	}
	for _, name := range nasMaterialNames {
		if !shaPattern.MatchString(p.Materials[name]) {
			return p, errors.New("closed NAS material pins required")
		}
	}
	if p.Scenario.Case == "eap-unenrolled" {
		if len(p.RejectMaterials) != 3 || !shaPattern.MatchString(p.RejectLeafSHA256) || p.RejectLeafSHA256 == p.ClientLeafSHA256 {
			return p, errors.New("independent rejection client pins required")
		}
		for _, n := range nasRejectMaterialNames {
			if !shaPattern.MatchString(p.RejectMaterials[n]) {
				return p, errors.New("closed rejection material pins required")
			}
		}
	} else if p.RejectMaterials != nil || p.RejectLeafSHA256 != "" {
		return p, errors.New("rejection material outside fixed case")
	}
	if validateECPlan(p.EC) != nil || validateCAClientPlan(p.RSA) != nil || p.EC.RootSHA256 != p.Materials["ec-root.pem"] || p.EC.IntermediateSHA256 != p.Materials["ec-intermediate.pem"] || p.EC.ClientCertificateSHA256 != p.Materials["client.pem"] || p.EC.ClientKeySHA256 != p.Materials["client.key"] || p.RSA.RootSHA256 != p.Materials["rsa-root.pem"] || p.RSA.IntermediateSHA256 != p.Materials["rsa-intermediate.pem"] || p.RSA.DecrypterSHA256 != p.Materials["rsa-decrypter.pem"] || p.RSA.BrokerCertificateSHA256 != p.Materials["broker.crt"] || p.RSA.BrokerTokenSHA256 != p.Materials["broker-token"] {
		return p, errors.New("NAS CA material/route pins differ")
	}
	one := func(v string) accounting.Attribute { return accounting.Attribute{Value: v, Count: 1} }
	if _, e := accounting.CanonicalKey(accounting.Raw{SourceIP: p.Scenario.NAS, NASIP: one(p.Scenario.NAS), Station: one(p.Station), Session: one(p.Scenario.Session)}); e != nil {
		return p, errors.New("planned canonical NAS station required")
	}
	return p, nil
}
