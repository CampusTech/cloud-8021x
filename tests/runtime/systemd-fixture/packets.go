package main

import (
	"bytes"
	"context"
	"crypto/md5" // RADIUS wire authentication, not a new cryptographic design.
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

type packetPlan struct {
	Target            string `json:"target"`
	Source            string `json:"source"`
	SecretFile        string `json:"secret_file"`
	EAPConfig         string `json:"eap_config"`
	InstalledEvidence string `json:"installed_evidence"`
	VLAN              int    `json:"vlan"`
	ExpectReject      bool   `json:"expect_reject"`
	Output            string `json:"output"`
}
type packetProof struct {
	Case          string `json:"case"`
	Target        string `json:"target"`
	PacketID      byte   `json:"packet_id"`
	Authenticator string `json:"request_authenticator"`
	Status        int    `json:"status"`
	ReceivedMin   int64  `json:"received_min"`
	ReceivedMax   int64  `json:"received_max"`
	ACK           bool   `json:"ack"`
}

func attributes(packet []byte) (map[byte][][]byte, error) {
	if len(packet) < 20 || int(packet[2])<<8|int(packet[3]) != len(packet) {
		return nil, errors.New("RADIUS length mismatch")
	}
	result := map[byte][][]byte{}
	for offset := 20; offset < len(packet); {
		if offset+2 > len(packet) {
			return nil, errors.New("truncated RADIUS attribute")
		}
		n := int(packet[offset+1])
		if n < 2 || offset+n > len(packet) {
			return nil, errors.New("invalid RADIUS attribute length")
		}
		result[packet[offset]] = append(result[packet[offset]], append([]byte(nil), packet[offset+2:offset+n]...))
		offset += n
	}
	return result, nil
}
func verifyResponse(reply, request, secret []byte) error {
	if len(reply) < 20 || len(request) < 20 || reply[1] != request[1] {
		return errors.New("RADIUS response identity mismatch")
	}
	if _, err := attributes(reply); err != nil {
		return err
	}
	authenticated := append([]byte(nil), reply...)
	copy(authenticated[4:20], request[4:20])
	authenticated = append(authenticated, secret...)
	sum := md5.Sum(authenticated)
	if !bytes.Equal(reply[4:20], sum[:]) {
		return errors.New("RADIUS response authenticator rejected")
	}
	return nil
}
func attr(raw []byte, kind byte, value []byte) []byte {
	return append(append(raw, kind, byte(len(value)+2)), value...)
}
func integer(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
func sendAccounting(plan packetPlan, secret, class, station []byte, session string, status, seconds, inBytes, outBytes uint32) (packetProof, error) {
	proof := packetProof{Case: session, Target: plan.Target, Status: int(status), ReceivedMin: time.Now().Unix()}
	raw := attr(nil, 40, integer(status))
	raw = attr(raw, 44, []byte(session))
	raw = attr(raw, 4, net.ParseIP(plan.Source).To4())
	raw = attr(raw, 31, station)
	raw = attr(raw, 25, class)
	raw = attr(raw, 46, integer(seconds))
	raw = attr(raw, 42, integer(inBytes))
	raw = attr(raw, 43, integer(outBytes))
	var id [1]byte
	if _, err := rand.Read(id[:]); err != nil {
		return proof, err
	}
	n := 20 + len(raw)
	packet := append([]byte{4, id[0], byte(n >> 8), byte(n)}, make([]byte, 16)...)
	packet = append(packet, raw...)
	sum := md5.Sum(append(append([]byte(nil), packet...), secret...))
	copy(packet[4:20], sum[:])
	proof.PacketID = id[0]
	proof.Authenticator = "0x" + hex.EncodeToString(sum[:])
	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(plan.Source)}, &net.UDPAddr{IP: net.ParseIP(plan.Target), Port: 1813})
	if err != nil {
		return proof, err
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return proof, err
	}
	if _, err := client.Write(packet); err != nil {
		return proof, err
	}
	reply := make([]byte, 4096)
	n, err = client.Read(reply)
	if err != nil {
		return proof, err
	}
	reply = reply[:n]
	if err := verifyResponse(reply, packet, secret); err != nil {
		return proof, err
	}
	if reply[0] != 5 {
		return proof, errors.New("accounting response code mismatch")
	}
	proof.ACK = true
	proof.ReceivedMax = time.Now().Unix()
	return proof, nil
}

// eap uses only eapol_test as a NAS. The relay observes authentic server replies;
// it never rewrites packets, server config, inventory, caches or unit state.
func eap(plan packetPlan, secret []byte) ([]byte, []byte, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(plan.Source), Port: 18120})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = conn.Close() }()
	var mu sync.Mutex
	var class, station []byte
	var failure error
	var outcome byte
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		requests := map[byte][]byte{}
		var client *net.UDPAddr
		buffer := make([]byte, 65535)
		fail := func(err error) { mu.Lock(); failure = err; mu.Unlock() }
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				fail(err)
				return
			}
			n, address, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				fail(err)
				return
			}
			packet := append([]byte(nil), buffer[:n]...)
			attrs, err := attributes(packet)
			if err != nil {
				fail(err)
				return
			}
			if address.IP.String() == plan.Target && address.Port == 1812 {
				request := requests[packet[1]]
				if client == nil || verifyResponse(packet, request, secret) != nil {
					fail(errors.New("unmatched or unauthenticated EAP reply"))
					return
				}
				if packet[0] == 2 || packet[0] == 3 {
					mu.Lock()
					outcome = packet[0]
					if packet[0] == 2 {
						if len(attrs[25]) != 1 || !bytes.HasPrefix(attrs[25][0], []byte("c8021x.1.")) {
							failure = errors.New("missing signed Class binding")
						} else {
							class = attrs[25][0]
						}
						if plan.VLAN == 0 {
							if len(attrs[64])+len(attrs[65])+len(attrs[81]) != 0 {
								failure = errors.New("unexpected VLAN attributes")
							}
						} else if len(attrs[64]) != 1 || len(attrs[65]) != 1 || len(attrs[81]) != 1 || !bytes.Equal(attrs[64][0], integer(13)) || !bytes.Equal(attrs[65][0], integer(6)) || string(attrs[81][0]) != strconv.Itoa(plan.VLAN) {
							failure = errors.New("numeric VLAN Tunnel-Type13/Tunnel-Medium-Type6 contract failed")
						}
					}
					mu.Unlock()
				}
				if _, err := conn.WriteToUDP(packet, client); err != nil {
					fail(err)
					return
				}
			} else {
				if address.IP.String() != plan.Source || packet[0] != 1 {
					fail(errors.New("unexpected relay sender"))
					return
				}
				client = address
				requests[packet[1]] = packet
				if len(attrs[31]) == 1 {
					mu.Lock()
					station = attrs[31][0]
					mu.Unlock()
				}
				if _, err := conn.WriteToUDP(packet, &net.UDPAddr{IP: net.ParseIP(plan.Target), Port: 1812}); err != nil {
					fail(err)
					return
				}
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "eapol_test", "-c", plan.EAPConfig, "-a", plan.Source, "-p", "18120", "-s", string(secret), "-t", "15", "-N", "61:d:19")
	// eapol_test emits sensitive synthetic TLS debugging: discard it; packet proof
	// is authenticated wire evidence, with exit status retained in the outcome.
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	err = command.Run()
	close(stop)
	<-done
	mu.Lock()
	defer mu.Unlock()
	if failure != nil {
		return nil, nil, failure
	}
	if plan.ExpectReject {
		if outcome != 3 || err == nil {
			return nil, nil, errors.New("expected real EAP rejection not observed")
		}
		return nil, nil, nil
	}
	if err != nil || outcome != 2 || len(class) == 0 || len(station) == 0 {
		return nil, nil, errors.New("real EAP-TLS acceptance incomplete")
	}
	return class, station, nil
}
func packetCommand() *cobra.Command {
	var input string
	cmd := &cobra.Command{Use: "packets", Short: "Send real packets to installed services from the owned NAS guest", RunE: func(_ *cobra.Command, _ []string) error {
		marker, err := read("/etc/cloud8021x-task11-fixture")
		if err != nil || marker != "synthetic-only-v1" || os.Geteuid() != 0 {
			return errors.New("owned root fixture required")
		}
		data, err := os.ReadFile(input)
		if err != nil {
			return err
		}
		var p packetPlan
		if err := json.Unmarshal(data, &p); err != nil {
			return err
		}
		if (p.Target != "10.203.11.21" && p.Target != "10.203.11.22") || p.Source != "10.203.11.40" || p.VLAN < 0 || p.VLAN > 4094 {
			return errors.New("nonfixture packet destination/source")
		}
		for _, path := range []string{p.SecretFile, p.EAPConfig, p.InstalledEvidence, p.Output} {
			if !filepath.IsAbs(path) || !strings.HasPrefix(filepath.Clean(path), "/var/lib/cloud8021x-task11/") {
				return errors.New("packet input/evidence must be owned fixture files")
			}
		}
		evidence, err := os.ReadFile(p.InstalledEvidence)
		if err != nil {
			return err
		}
		var installed snapshot
		if json.Unmarshal(evidence, &installed) != nil {
			return errors.New("invalid installed audit")
		}
		expected := "task11-green-primary"
		if p.Target == "10.203.11.22" {
			expected = "task11-green-secondary"
		}
		if installed.Hostname != expected || installed.UnitState["freeradius.service"]["ActiveState"] != "active" || installed.UnitState["cloud-8021x.service"]["ActiveState"] != "active" {
			return errors.New("matching installed-service audit required")
		}
		secret, err := os.ReadFile(p.SecretFile)
		if err != nil {
			return err
		}
		secret = bytes.TrimSpace(secret)
		if !bytes.HasPrefix(secret, []byte("task11-")) {
			return errors.New("synthetic shared secret required")
		}
		class, station, err := eap(p, secret)
		if err != nil {
			return err
		}
		proofs := []packetProof{}
		if !p.ExpectReject {
			var suffix [8]byte
			if _, err := rand.Read(suffix[:]); err != nil {
				return err
			}
			session := "task11-" + hex.EncodeToString(suffix[:])
			for _, event := range []struct{ status, seconds, input, output uint32 }{{1, 0, 0, 0}, {3, 60, 1000, 2000}, {2, 90, 1600, 2900}} {
				proof, err := sendAccounting(p, secret, class, station, session, event.status, event.seconds, event.input, event.output)
				if err != nil {
					return err
				}
				proofs = append(proofs, proof)
			}
		}
		file, err := os.OpenFile(p.Output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer func() { _ = file.Close() }()
		return json.NewEncoder(file).Encode(map[string]any{"schema": 1, "target": p.Target, "rejected": p.ExpectReject, "installed_boot_id": installed.BootID, "accounting": proofs, "limit": "packet ACKs require separate exact SQL/collector reconciliation"})
	}}
	cmd.Flags().StringVar(&input, "plan", "", "owned synthetic packet plan JSON")
	return cmd
}
