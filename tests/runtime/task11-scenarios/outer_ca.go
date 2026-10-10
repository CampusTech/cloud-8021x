package main

import (
	"context"
	"errors"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

func executeCAActions(ctx context.Context, s *outerStore, p nasPrivatePlan, a outerAttempt, phase string, history []retiredOperation, invoke measuredInvoker) ([]retiredOperation, error) {
	authority := caseAuthority(p.Scenario)
	if authority == "" || invoke == nil {
		return nil, errors.New("fixed genuine CA scenario required")
	}
	if phase == "original" {
		if len(history) != 0 {
			return nil, errors.New("retained original attempt refuses rerun")
		}
	} else if phaseNotAlreadyAttempted(history, phase) != nil {
		return nil, errors.New("complete earlier genuine CA phase required")
	}
	operations := append([]retiredOperation(nil), history...)
	sequence := len(history)
	call := func(r sc.Request) (retiredOperation, error) {
		sequence++
		if sequence > sc.MaxSequence {
			return retiredOperation{}, errors.New("bounded CA history exhausted")
		}
		r.Schema = 1
		r.AttemptID = a.AttemptID
		r.Sequence = sequence
		r.Pins = planPins(p, a.PlanSHA256)
		if e := r.Validate(); e != nil {
			return retiredOperation{}, e
		}
		op, e := invoke(ctx, r)
		if e == nil {
			operations = append(operations, op)
		}
		return op, e
	}
	readIssued := func(issued retiredOperation, previous *sc.CAObservation) (sc.CAObservation, error) {
		selection, raw, e := publishIssuedSelection(s, issued)
		if e != nil {
			return sc.CAObservation{}, e
		}
		op, e := call(sc.Request{Action: "read-ca-issued", SelectionSHA256: digestBytes(raw), IssuanceSequence: selection.IssuanceSequence})
		if e != nil || op.result.CAIssued == nil {
			return sc.CAObservation{}, errors.New("actual selected issued DB observation absent")
		}
		observed := *op.result.CAIssued
		if e = reconcileCAStored(selection, raw, *issued.result.CA, observed); e != nil {
			return observed, e
		}
		if previous != nil {
			if e = preserveCAStored(*previous, observed); e != nil {
				return observed, e
			}
		}
		return observed, nil
	}
	var original retiredOperation
	var originalRow *sc.CAObservation
	if phase != "original" {
		var e error
		original, originalRow, e = existingCAOriginal(history, authority)
		if e != nil {
			return nil, e
		}
		if _, e = readIssued(original, originalRow); e != nil {
			return nil, e
		}
	}
	var adopted retiredOperation
	var adoptedRow *sc.CAObservation
	if phase == "passive" {
		for _, op := range history {
			if op.result.CA != nil && op.result.CA.Phase == "adopted" {
				if adopted.raw != nil {
					return nil, errors.New("ambiguous adopted CA history")
				}
				adopted = op
			}
			if op.result.CAIssued != nil && adopted.raw != nil && op.result.CAIssued.IssuanceResultSHA256 == digestBytes(adopted.raw) {
				v := *op.result.CAIssued
				adoptedRow = &v
			}
		}
		if adopted.raw == nil || adoptedRow == nil {
			return nil, errors.New("genuine adopted issuance and stored DB row required")
		}
		if _, e := readIssued(adopted, adoptedRow); e != nil {
			return nil, e
		}
	}
	request := sc.Request{Action: "nas-ca-" + phase, Authority: authority}
	if authority == "rsa" && phase != "original" {
		selection, raw, e := publishIssuedSelection(s, original)
		if e != nil {
			return nil, e
		}
		request.SelectionSHA256 = digestBytes(raw)
		request.IssuanceSequence = selection.IssuanceSequence
	}
	issued, e := call(request)
	if e != nil || issued.result.CA == nil {
		return nil, errors.New("actual fixed CA exchange failed")
	}
	ca := issued.result.CA
	root, inter := p.EC.RootSHA256, p.EC.IntermediateSHA256
	originalPeer := p.EC.Peer
	if authority == "rsa" {
		root, inter = p.RSA.RootSHA256, p.RSA.IntermediateSHA256
		originalPeer = p.RSA.Blue
	}
	peer, e := phaseCAPeer(originalPeer, phase)
	if e != nil || ca.Authority != authority || ca.Phase != phase || ca.Peer != peer || ca.OriginalRootSHA256 != root || ca.OriginalIntermediateSHA256 != inter {
		return nil, errors.New("genuine CA phase or preserved signer chain differs")
	}
	if phase == "passive" {
		if ca.Issued != nil || ca.Response.ChainVerified || ca.Response.SignatureVerified || ca.Response.TransactionBound {
			return nil, errors.New("passive authority unexpectedly issued")
		}
		// This negative is only a client observation. It cannot replace independent
		// passive units, reboot proof, journal mutation audit or actual DB evidence.
		if _, e = readIssued(original, originalRow); e != nil {
			return nil, e
		}
		if _, e = readIssued(adopted, adoptedRow); e != nil {
			return nil, e
		}
		return operations, nil
	}
	if ca.Issued == nil {
		return nil, errors.New("genuine CA issuance missing")
	}
	if phase == "adopted" {
		old := original.result.CA.Issued
		if ca.Issued.PublicKeySHA256 != old.PublicKeySHA256 || ca.Issued.Subject != old.Subject || ca.Issued.Serial == old.Serial || ca.Issued.LeafDERSHA256 == old.LeafDERSHA256 {
			return nil, errors.New("genuine same-client adopted renewal missing")
		}
	}
	if _, e = readIssued(issued, nil); e != nil {
		return nil, e
	}
	return operations, nil
}
