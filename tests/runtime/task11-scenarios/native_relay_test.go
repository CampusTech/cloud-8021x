package main

import (
	"bytes"
	"net"
	"testing"
)

func TestNativeRelayPreservesBytesAndRefusesForeignPeers(t *testing.T) {
	p := pureNASPlan()
	secret := []byte("task11-private-nas-secret")
	relay := nativeRelay{plan: p, secret: secret}
	client := &net.UDPAddr{IP: net.ParseIP("10.203.11.40"), Port: 31234}
	request := pureEAPRequest(p, secret)
	before := bytes.Clone(request)
	to, e := relay.forward(client, request)
	if e != nil || to == nil || to.IP.String() != p.Scenario.Target || to.Port != 1812 || !bytes.Equal(request, before) {
		t.Fatal("fixed unchanged native request relay absent", e)
	}
	attrs := append(numericTunnel(64, 13), numericTunnel(65, 6)...)
	attrs = append(attrs, attribute(81, []byte("120"))...)
	attrs = append(attrs, attribute(25, []byte("private-class"))...)
	attrs = append(attrs, attribute(79, []byte{3, 1, 0, 4})...)
	response := pureEAPReply(t, request, secret, 2, attrs)
	before = bytes.Clone(response)
	to, e = relay.forward(&net.UDPAddr{IP: net.ParseIP(p.Scenario.Target), Port: 1812}, response)
	if e != nil || to == nil || to.String() != client.String() || !relay.final.Accepted || relay.class != "private-class" || !bytes.Equal(response, before) {
		t.Fatal("genuine final reply not observed/forwarded unchanged", e)
	}
	for _, peer := range []string{"10.203.11.22", "10.203.11.31", "127.0.0.1"} {
		fresh := nativeRelay{plan: p, secret: secret}
		_, _ = fresh.forward(client, request)
		if _, e = fresh.forward(&net.UDPAddr{IP: net.ParseIP(peer), Port: 1812}, response); e == nil {
			t.Fatal("unselected server reply forwarded")
		}
	}
	fresh := nativeRelay{plan: p, secret: secret}
	if _, e = fresh.forward(&net.UDPAddr{IP: net.ParseIP(p.Scenario.Target), Port: 1812}, response); e == nil {
		t.Fatal("unmatched native response accepted")
	}
	_, _ = fresh.forward(client, request)
	changed := *client
	changed.Port++
	if _, e = fresh.forward(&changed, request); e == nil {
		t.Fatal("native client source changed mid exchange")
	}
	fresh.exchanges = 256
	if _, e = fresh.forward(client, request); e == nil {
		t.Fatal("unbounded native exchange accepted")
	}
}
