package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	sc "github.com/CampusTech/cloud-8021x/tests/runtime/task11-acceptance/scenariocontract"
)

// The controller supplies the genuinely enrolled NAS root/net descriptors and
// scoped cgroup. This function never starts a server or manufactures a reply.
func runNativeEAP(ctx context.Context, p nasPrivatePlan, secret []byte, executable *os.File) (sc.EAPResult, string, error) {
	var actual sc.EAPResult
	if ctx == nil || executable == nil {
		return actual, "", errors.New("fixed retained native execution required")
	}
	args, e := fixedEAPArguments(p, secret)
	if e != nil {
		return actual, "", e
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if e = ctx.Err(); e != nil {
		return actual, "", errors.New("native operation already cancelled")
	}
	conn, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.203.11.40"), Port: 18120})
	if e != nil {
		return actual, "", errors.New("fixed private native relay unavailable")
	}
	defer func() { _ = conn.Close() }()
	relay := nativeRelay{plan: p, secret: secret}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 4097)
		defer clear(buffer)
		for {
			select {
			case <-stop:
				done <- nil
				return
			case <-ctx.Done():
				done <- errors.New("bounded native relay expired")
				return
			default:
			}
			if conn.SetReadDeadline(time.Now().Add(100*time.Millisecond)) != nil {
				done <- errors.New("native relay deadline unavailable")
				return
			}
			n, address, err := conn.ReadFromUDP(buffer)
			if err != nil {
				select {
				case <-stop:
					done <- nil
					return
				default:
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					continue
				}
				done <- errors.New("native relay read failed")
				return
			}
			target, err := relay.forward(address, buffer[:n])
			if err != nil {
				done <- err
				return
			}
			written, err := conn.WriteToUDP(buffer[:n], target)
			if err != nil || written != n {
				done <- errors.New("unchanged native relay write failed")
				return
			}
			if relay.final.Accepted || relay.final.Rejected {
				done <- nil
				return
			}
		}
	}()
	// FD3 is inherited from the already measured installed file, avoiding a path
	// replacement between measurement and exec. Missing owned proc is refusal.
	command := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	command.Args[0] = "/usr/bin/eapol_test"
	command.ExtraFiles = []*os.File{executable}
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	childErr := command.Run()
	close(stop)
	_ = conn.Close()
	relayErr := <-done
	clear(relay.request)
	if relayErr != nil {
		return actual, "", relayErr
	}
	actual = relay.final
	if actual.Accepted && childErr == nil && relay.class != "" {
		return actual, relay.class, nil
	}
	var exit *exec.ExitError
	if actual.Rejected && ctx.Err() == nil && errors.As(childErr, &exit) && exit.ExitCode() > 0 {
		return actual, "", nil
	}
	return sc.EAPResult{}, "", errors.New("actual native EAP child/outcome incomplete")
}
func sendNativeAccounting(ctx context.Context, v nativeTransmission, secret []byte) (sc.AccountingPacketResult, error) {
	result := sc.AccountingPacketResult{Peer: v.peer, Status: v.event.Status, Duration: v.event.Duration, UploadBytes: v.event.Upload, DownloadBytes: v.event.Download}
	if ctx == nil || (v.peer != "10.203.11.21" && v.peer != "10.203.11.22") || len(v.packet) < 20 {
		return result, errors.New("fixed prepared native transmission required")
	}
	if ctx.Err() != nil {
		return result, errors.New("native transmission already cancelled")
	}
	result.PacketID = v.packet[1]
	result.RequestAuthenticator = hex.EncodeToString(v.packet[4:20])
	client, e := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.203.11.40")}, &net.UDPAddr{IP: net.ParseIP(v.peer), Port: 1813})
	if e != nil {
		return result, errors.New("fixed accounting socket unavailable")
	}
	defer func() { _ = client.Close() }()
	deadline := time.Now().Add(3 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if client.SetDeadline(deadline) != nil {
		return result, errors.New("accounting deadline unavailable")
	}
	result.SentAt = time.Now().UTC()
	n, e := client.Write(v.packet)
	if e != nil || n != len(v.packet) {
		return result, errors.New("actual accounting write incomplete")
	}
	buffer := make([]byte, 4097)
	defer clear(buffer)
	n, e = client.Read(buffer)
	result.CompletedAt = time.Now().UTC()
	if e != nil {
		if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
			return result, nil
		}
		return result, errors.New("actual accounting response read failed")
	}
	if _, e = validateResponse(buffer[:n], v.packet, secret, 5); e != nil {
		return result, e
	}
	result.ResponseCode = 5
	result.ACK = true
	result.ResponseAuthenticatorSHA256 = digestBytes(buffer[4:20])
	return result, nil
}
