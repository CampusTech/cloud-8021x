package native

import (
	"context"
	"crypto/hmac"
	"crypto/md5" // RADIUS wire protocol requires MD5; not used for a new cryptosystem.
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// ProbeStatus proves only native process responsiveness, not device EAP success.
// Maintenance also requires authenticated peer policy/config/certificate readiness.
func ProbeStatus(ctx context.Context, address string, secret []byte) error {
	target, e := netip.ParseAddrPort(address)
	if e != nil || (!target.Addr().IsPrivate() && !target.Addr().IsLoopback()) || len(secret) < 32 || len(secret) > 256 {
		return errors.New("invalid private native health target")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	dialer := net.Dialer{}
	c, e := dialer.DialContext(ctx, "udp", address)
	if e != nil {
		return errors.New("native health unknown")
	}
	defer func() { _ = c.Close() }()
	deadline, _ := ctx.Deadline()
	if e = c.SetDeadline(deadline); e != nil {
		return errors.New("native health deadline failed")
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	request := make([]byte, 38)
	request[0] = 12
	binary.BigEndian.PutUint16(request[2:4], 38)
	if _, e = rand.Read(request[4:20]); e != nil {
		return errors.New("native health nonce failed")
	}
	request[1] = request[4]
	request[20], request[21] = 80, 18
	mac := hmac.New(md5.New, secret)
	_, _ = mac.Write(request)
	copy(request[22:], mac.Sum(nil))
	if _, e = c.Write(request); e != nil {
		return errors.New("native health unknown")
	}
	response := make([]byte, 4097)
	n, e := c.Read(response)
	if e != nil || n < 38 || n > 4096 {
		return errors.New("native health unknown")
	}
	response = response[:n]
	if response[0] != 2 || response[1] != request[1] || int(binary.BigEndian.Uint16(response[2:4])) != n {
		return errors.New("native health response rejected")
	}
	auth := append([]byte(nil), response[4:20]...)
	copy(response[4:20], request[4:20])
	hash := md5.New()
	_, _ = hash.Write(response)
	_, _ = hash.Write(secret)
	if !hmac.Equal(auth, hash.Sum(nil)) {
		return errors.New("native health response authenticator rejected")
	}
	offset := -1
	for i := 20; i < n; {
		if i+2 > n || int(response[i+1]) < 2 || i+int(response[i+1]) > n {
			return errors.New("native health attributes malformed")
		}
		if response[i] == 80 {
			if response[i+1] != 18 || offset != -1 {
				return errors.New("native health requires exactly one message authenticator")
			}
			offset = i + 2
		}
		i += int(response[i+1])
	}
	if offset < 0 {
		return errors.New("native health missing message authenticator")
	}
	message := append([]byte(nil), response[offset:offset+16]...)
	clear(response[offset : offset+16])
	mac = hmac.New(md5.New, secret)
	_, _ = mac.Write(response)
	if !hmac.Equal(message, mac.Sum(nil)) {
		return errors.New("native health message authenticator rejected")
	}
	return nil
}
