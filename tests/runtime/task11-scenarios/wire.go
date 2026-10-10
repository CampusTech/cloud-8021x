package main

import (
	"crypto/md5" // #nosec G501 -- RADIUS authenticators are protocol-mandated MD5.
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
)

// validateResponse authenticates unchanged actual server bytes before inspecting
// numeric VLAN attributes. It never constructs or rewrites a server response.
func validateResponse(packet, request, secret []byte, want byte) (string, error) {
	if len(secret) < 8 || len(request) < 20 || len(packet) < 20 || len(packet) > 4096 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || packet[1] != request[1] || packet[0] != want {
		return "", errors.New("invalid bounded RADIUS response")
	}
	authenticated := append([]byte(nil), packet...)
	copy(authenticated[4:20], request[4:20])
	authenticated = append(authenticated, secret...)
	sum := md5.Sum(authenticated) // #nosec G401 -- RFC2865 response authenticator.
	clear(authenticated)
	if subtle.ConstantTimeCompare(packet[4:20], sum[:]) != 1 {
		return "", errors.New("RADIUS response authenticator mismatch")
	}
	attrs, err := parseAttributes(packet[20:])
	if err != nil {
		return "", err
	}
	if want == 3 {
		for _, kind := range []byte{25, 64, 65, 81} {
			if len(attrs[kind]) != 0 {
				return "", errors.New("Access-Reject cannot carry Class or VLAN assignment")
			}
		}
	}
	if want != 2 {
		return "", nil
	}
	numeric := func(kind byte, want uint32) bool {
		v := attrs[kind]
		return len(v) == 1 && len(v[0]) == 4 && binary.BigEndian.Uint32(v[0]) == want
	}
	if !numeric(64, 13) || !numeric(65, 6) || len(attrs[81]) != 1 || string(attrs[81][0]) != "120" || len(attrs[25]) != 1 {
		return "", errors.New("exact numeric13/6/VLAN120/single Class required")
	}
	return string(attrs[25][0]), nil
}
func deriveExpectations(p scenarioPlan, station, token string, key []byte, receipt, epoch time.Time) (expectations, error) {
	var result expectations
	if err := validatePlan(p); err != nil {
		return result, err
	}
	if !epoch.Equal(p.CollectionEpoch) {
		return result, errors.New("caller epoch differs from immutable planned epoch")
	}
	epoch = p.CollectionEpoch
	identity := binding.Verify(key, []string{token}, "task11", []string{station}, receipt, binding.MaxAge)
	if identity == nil || identity.DeviceID != "fleet:1" || identity.VLAN == nil || *identity.VLAN != 120 || receipt.Before(epoch) {
		return result, errors.New("genuine verified Class/collection epoch required")
	}
	state := accounting.State{}
	seen := map[string]bool{}
	one := func(v string) accounting.Attribute { return accounting.Attribute{Value: v, Count: 1} }
	for _, planned := range p.Events {
		raw := accounting.Raw{SourceIP: "10.203.11.40", NASIP: one("10.203.11.40"), Station: one(station), Session: one(p.Session), Status: one(strconv.Itoa(planned.Status)), Duration: one(strconv.FormatUint(uint64(planned.Duration), 10)), Input: one(strconv.FormatUint(planned.Upload&0xffffffff, 10)), Output: one(strconv.FormatUint(planned.Download&0xffffffff, 10)), InputHigh: one(strconv.FormatUint(planned.Upload>>32, 10)), OutputHigh: one(strconv.FormatUint(planned.Download>>32, 10)), Class: one(token), Received: receipt, Location: "task11", Client: "task11-nas", Host: "task11-" + p.Node}
		event, err := accounting.Normalize(raw, key, binding.MaxAge)
		if err != nil || event.Identity == nil {
			return result, errors.New("planned native event normalization failed")
		}
		if seen[event.ID] {
			continue
		}
		seen[event.ID] = true
		result.Events = append(result.Events, event)
		next, interval, _ := accounting.ApplyEpoch(state, event, epoch)
		state = next
		if interval != nil {
			result.Intervals = append(result.Intervals, *interval)
			result.Upload += interval.Upload
			result.Download += interval.Download
			result.Seconds += interval.Seconds
		}
	}
	return result, nil
}
