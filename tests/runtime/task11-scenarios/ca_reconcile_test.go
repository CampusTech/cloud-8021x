package main

import (
	"bytes"
	"encoding/json"
	"testing"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func TestCAReconciliationBindsActualRetiredIssuanceAndExactStoredDERMetadata(t *testing.T) {
	f := purePriorNASInput(t)
	var result sc.Result
	if e := json.Unmarshal(f.input.Prior.ResultBytes, &result); e != nil {
		t.Fatal(e)
	}
	selection, raw, e := issuedSelection(result, f.input.Prior.ResultBytes)
	if e != nil {
		t.Fatal(e)
	}
	if selection.ResultSHA256 != digestBytes(f.input.Prior.ResultBytes) || selection.LeafDERSHA256 != digestBytes(result.CA.Issued.LeafDER) {
		t.Fatal("selection not derived from actual retired public leaf")
	}
	observation := sc.CAObservation{Authority: "rsa", Database: "stepca_rsa", ReadOnly: true, Isolation: "repeatable-read", Serial: selection.Serial, SelectionSHA256: digestBytes(raw), IssuanceResultSHA256: selection.ResultSHA256, LeafDERSHA256: selection.LeafDERSHA256, CertificateKey: []byte(selection.Serial), CertificateDER: append([]byte(nil), result.CA.Issued.LeafDER...), CertificateDataPresent: true, CertificateDataKey: []byte(selection.Serial), CertificateData: []byte(` { "provisioner": { "id":"x", "name":"wifi-scep", "type":"SCEP" } } `)}
	if e = reconcileCAStored(selection, raw, *result.CA, observation); e != nil {
		t.Fatal(e)
	}
	if e = preserveCAStored(observation, observation); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"missing-metadata", "changed-der", "key", "whitespace", "authority", "result"} {
		bad := observation
		switch name {
		case "missing-metadata":
			bad.CertificateDataPresent = false
			bad.CertificateData = nil
		case "changed-der":
			bad.CertificateDER = append([]byte{0}, bad.CertificateDER...)
		case "key":
			bad.CertificateKey = []byte("123")
		case "whitespace":
			bad.CertificateData = append([]byte(" "), bad.CertificateData...)
		case "authority":
			bad.Authority = "ec"
		case "result":
			bad.IssuanceResultSHA256 = ""
		}
		if name == "whitespace" {
			if preserveCAStored(observation, bad) == nil {
				t.Fatal("opaque metadata canonicalized")
			}
		} else if reconcileCAStored(selection, raw, *result.CA, bad) == nil {
			t.Fatal("unbound DB evidence accepted", name)
		}
	}
	unretired := result
	unretired.Retired = false
	if _, _, e = issuedSelection(unretired, f.input.Prior.ResultBytes); e == nil {
		t.Fatal("unretired issuance selected")
	}
	if !bytes.Equal(observation.CertificateDER, result.CA.Issued.LeafDER) {
		t.Fatal("source DER rewritten")
	}
}
