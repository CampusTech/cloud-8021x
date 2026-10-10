package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"reflect"

	"github.com/CampusTech/cloud-8021x/internal/domain"
)

type producerInputs struct {
	Input, Manifest, Platform, PlatformPlan, Enrollment []byte
	Files                                               map[string][]byte
	Configs                                             map[string][]byte
}
type preparedNAS struct{ Materials, Plans map[string][]byte }

func prepareNASBundle(in producerInputs) (preparedNAS, error) {
	out := preparedNAS{Materials: map[string][]byte{}, Plans: map[string][]byte{}}
	v, e := validateProducerInputs(in)
	if e != nil {
		return out, e
	}
	var cloud producerCloud
	if strictJSON(in.Files["api/seed.json"], 1<<20, &cloud) != nil || cloud.Schema != 1 || cloud.ProjectID != v.Input.Project || cloud.ProjectNumber != v.Input.ProjectNumber {
		return out, errors.New("fixed original cloud seed differs")
	}
	secret := func(name string) ([]byte, error) {
		versions := cloud.Secrets["projects/"+v.Input.ProjectNumber+"/secrets/"+name]
		b, err := base64.StdEncoding.DecodeString(versions["1"])
		if len(versions) != 1 || err != nil || len(b) == 0 || len(b) > 64<<10 {
			return nil, errors.New("exact original version1 secret required")
		}
		return b, nil
	}
	for name, path := range producerMaterialPaths {
		out.Materials[name] = bytes.Clone(in.Files[path])
	}
	for name, id := range map[string]string{"radius-secret": "radius-task11-secret", "broker-token": "scep-broker-token", "class-key": "radius-accounting-class-key"} {
		b, err := secret(id)
		if err != nil || !bytes.Equal(b, out.Materials[name]) {
			clear(b)
			return out, errors.New("published credential differs from preserved version1")
		}
		clear(b)
	}
	out.Materials["rsa-decrypter.pem"], e = secret("smallstep-rsa-scep-decrypter-cert")
	if e != nil {
		return out, e
	}
	pins := map[string]string{}
	for name, b := range out.Materials {
		pins[name] = digestBytes(b)
	}
	// Only the negative plan receives these additional fixed pins. Positive
	// plans retain the unchanged thirteen-material authority.
	rejectPins := map[string]string{}
	for name, path := range producerRejectMaterialPaths {
		out.Materials[name] = bytes.Clone(in.Files[path])
		rejectPins[name] = digestBytes(out.Materials[name])
	}
	ec := ecClientPlan{Phase: "original", Peer: "10.203.11.31", DNS: v.Input.ECDNS, RootSHA256: pins["ec-root.pem"], IntermediateSHA256: pins["ec-intermediate.pem"], ClientCertificateSHA256: pins["client.pem"], ClientKeySHA256: pins["client.key"]}
	rsa := caClientPlan{Blue: "10.203.11.31", DNS: v.Input.RSADNS, Provisioner: "wifi-scep", RootSHA256: pins["rsa-root.pem"], IntermediateSHA256: pins["rsa-intermediate.pem"], DecrypterSHA256: pins["rsa-decrypter.pem"], BrokerCertificateSHA256: pins["broker.crt"], BrokerTLSName: "localhost", BrokerTokenSHA256: pins["broker-token"]}
	block, _ := pem.Decode(out.Materials["client.pem"])
	if block == nil || block.Type != "CERTIFICATE" {
		return out, errors.New("preserved original client leaf absent")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil || leaf.Subject.CommonName != "11111111-2222-4333-8444-555555555555" {
		return out, errors.New("preserved fixture device identity differs")
	}
	fingerprint := digestBytes(leaf.Raw)
	snapshot, e := domain.DecodeSnapshot(bytes.NewReader(in.Files["source/etc/freeradius/3.0/device-policy-cache.json"]))
	if e != nil || snapshot.Version != 2 {
		return out, errors.New("original fingerprint policy unavailable")
	}
	for _, record := range []*domain.DeviceRecord{snapshot.Identities[leaf.Subject.CommonName], snapshot.Certificates[fingerprint]} {
		if record == nil || record.DeviceID != "fleet:1" || !record.Enrolled || !reflect.DeepEqual(record.Groups, []domain.GroupID{"fleet:1"}) || record.ObservedAt == nil || *record.ObservedAt != domain.Unix(v.Input.ObservedAt) {
			return out, errors.New("independent original device/group expectation differs")
		}
	}
	rejectLeaf, err := validateRejectClient(ec, out.Materials, rejectPins)
	if err != nil {
		return out, err
	}
	if err = rejectClientAbsent(rejectLeaf, snapshot, in.Files["source/var/lib/cloud-8021x/certificate-state.json"]); err != nil {
		return out, err
	}
	server, _ := pem.Decode(in.Files["source/etc/freeradius/3.0/certs/server.pem"])
	if server == nil {
		return out, errors.New("original RADIUS certificate missing")
	}
	cert, e := x509.ParseCertificate(server.Bytes)
	if e != nil || cert.VerifyHostname(nativeServerDNS) != nil {
		return out, errors.New("original protected RADIUS SAN differs")
	}
	for _, name := range producerCases {
		node, target, namespace := "green-primary", "10.203.11.21", "c11-gp"
		if name == "ha-primary" {
			node, target, namespace = "green-secondary", "10.203.11.22", "c11-gs"
		}
		scenario := name
		if name == "ongoing-interim" || name == "ongoing-stop" {
			scenario = "ongoing-baseline"
		}
		if name == "ca-ec-continuity" || name == "ca-rsa-continuity" {
			scenario = "ca-continuity"
		}
		events := []plannedEvent{{Status: 1}, {Status: 3, Duration: 60, Upload: 1000, Download: 2000}, {Status: 2, Duration: 90, Upload: 1600, Download: 2900}}
		if name == "ongoing-interim" {
			events = events[1:]
		} else if name == "ongoing-stop" {
			events = events[2:]
		} else if scenario == "ca-continuity" {
			events = []plannedEvent{{Status: 1}}
		}
		if name == "eap-unenrolled" {
			events = nil
		}
		outage := 0
		if name == "postgres-outage" || name == "business-outage" {
			outage = 5
		}
		plan := nasPrivatePlan{Schema: 1, OriginalSeedSHA256: v.Input.OriginalManifestSHA256, Materials: pins, EC: ec, RSA: rsa, ClientLeafSHA256: fingerprint, Station: "AA:BB:CC:DD:EE:FF", Scenario: scenarioPlan{Schema: 1, Scenario: scenario, Case: name, PlatformSHA256: digestBytes(in.Platform), EnrollmentSHA256: digestBytes(in.Enrollment), ApplicationSHA256: v.Enrollment.ApplicationSHA256, SelfSHA256: v.Platform.Helpers["task11-scenarios"].SHA256, OriginalSeedSHA256: v.Input.OriginalManifestSHA256, CollectionEpoch: v.Input.CollectionEpoch, Node: node, Target: target, Namespace: namespace, Machine: "task11-" + node, NAS: "10.203.11.40", NASNamespace: "c11-nas", Session: "task11-" + name, Events: events, OutageSeconds: outage}}
		if name == "eap-unenrolled" {
			plan.RejectMaterials = rejectPins
			plan.RejectLeafSHA256 = digestBytes(rejectLeaf.Raw)
		}
		raw, err := json.Marshal(plan)
		if err != nil {
			return out, err
		}
		if _, err = decodeNASPlan(raw, digestBytes(raw)); err != nil {
			return out, err
		}
		if err = validateNativeMaterials(plan, out.Materials); err != nil {
			return out, err
		}
		if _, err = parsePinnedRSAClientKey(plan, out.Materials["scep-client.key"]); err != nil {
			return out, err
		}
		// Validate preserved RSA authority, recipient and genuine broker TLS pins
		// without a socket or any initial signer/certificate generation.
		root, err := singlePinnedCertificate(out.Materials["rsa-root.pem"], pins["rsa-root.pem"])
		if err != nil || !root.IsCA {
			return out, errors.New("RSA root differs")
		}
		intermediate, err := singlePinnedCertificate(out.Materials["rsa-intermediate.pem"], pins["rsa-intermediate.pem"])
		if err != nil || !intermediate.IsCA || intermediate.CheckSignatureFrom(root) != nil {
			return out, errors.New("RSA intermediate differs")
		}
		if _, err = singlePinnedCertificate(out.Materials["rsa-decrypter.pem"], pins["rsa-decrypter.pem"]); err != nil {
			return out, err
		}
		broker, err := pinnedCAClient(rsa, out.Materials["rsa-root.pem"], out.Materials["broker.crt"], true, nil)
		if err != nil {
			return out, err
		}
		broker.CloseIdleConnections()
		out.Plans[name+".json"] = raw
	}
	return out, nil
}
