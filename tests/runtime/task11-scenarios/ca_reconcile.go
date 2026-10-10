package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func issuedSelection(result sc.Result, raw []byte) (sc.CASelection, []byte, error) {
	var decoded sc.Result
	if len(raw) == 0 || len(raw) > 32<<10 || strictJSON(raw, 32<<10, &decoded) != nil || !reflect.DeepEqual(decoded, result) || !result.Retired || result.CA == nil || result.CA.Issued == nil || result.Kind != "scenario-operation" || result.Action != "nas-ca-"+result.CA.Phase || result.CA.Phase == "passive" || !result.CA.Response.ChainVerified || !result.CA.Response.SignatureVerified || !result.CA.Response.TransactionBound {
		return sc.CASelection{}, nil, errors.New("actual retired verified issued result required")
	}
	ca := result.CA
	leaf := ca.Issued
	selection := sc.CASelection{Schema: 1, AttemptID: result.AttemptID, IssuanceSequence: result.Sequence, ResultSHA256: digestBytes(raw), Authority: ca.Authority, Serial: leaf.Serial, LeafDERSHA256: leaf.LeafDERSHA256, OriginalRootSHA256: ca.OriginalRootSHA256, OriginalIntermediateSHA256: ca.OriginalIntermediateSHA256}
	encoded, e := json.Marshal(selection)
	if e != nil {
		return selection, nil, e
	}
	if _, e = sc.DecodeCASelection(encoded); e != nil {
		return selection, nil, e
	}
	if digestBytes(leaf.LeafDER) != selection.LeafDERSHA256 {
		return selection, nil, errors.New("issued leaf bytes differ")
	}
	return selection, encoded, nil
}
func reconcileCAStored(s sc.CASelection, raw []byte, ca sc.CAResult, a sc.CAObservation) error {
	decoded, e := sc.DecodeCASelection(raw)
	if e != nil || decoded != s || ca.Issued == nil || ca.Authority != s.Authority || ca.OriginalRootSHA256 != s.OriginalRootSHA256 || ca.OriginalIntermediateSHA256 != s.OriginalIntermediateSHA256 || ca.Issued.Serial != s.Serial || ca.Issued.LeafDERSHA256 != s.LeafDERSHA256 || a.Authority != s.Authority || a.Serial != s.Serial || a.SelectionSHA256 != digestBytes(raw) || a.IssuanceResultSHA256 != s.ResultSHA256 || a.LeafDERSHA256 != s.LeafDERSHA256 || !a.ReadOnly || a.Isolation != "repeatable-read" || !bytes.Equal(a.CertificateKey, []byte(s.Serial)) || !bytes.Equal(a.CertificateDER, ca.Issued.LeafDER) || digestBytes(a.CertificateDER) != s.LeafDERSHA256 {
		return errors.New("actual selected issued certificate row differs")
	}
	database := "stepca"
	if s.Authority == "rsa" {
		database = "stepca_rsa"
	}
	if a.Database != database {
		return errors.New("original CA database identity differs")
	}
	if s.Authority == "rsa" {
		if !a.CertificateDataPresent || !bytes.Equal(a.CertificateDataKey, a.CertificateKey) || len(a.CertificateData) == 0 {
			return errors.New("actual original SCEP metadata missing")
		}
	} else if a.CertificateDataPresent || len(a.CertificateDataKey) != 0 || len(a.CertificateData) != 0 {
		return errors.New("legacy EC renewal metadata absence changed")
	}
	return nil
}
func preserveCAStored(before, after sc.CAObservation) error {
	if !reflect.DeepEqual(before, after) {
		return errors.New("preserved CA row bytes or explicit metadata presence changed")
	}
	return nil
}
