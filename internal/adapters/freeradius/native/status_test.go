package native

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestStatusProbeAuthenticatesResponse(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "corrupt"}[corrupt], func(t *testing.T) {
			s, e := net.ListenPacket("udp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer func() { _ = s.Close() }()
			secret := []byte("fixture-health-secret-32-bytes-long")
			go func() {
				b := make([]byte, 4096)
				n, peer, e := s.ReadFrom(b)
				if e != nil {
					return
				}
				if n != 38 || b[0] != 12 {
					return
				}
				response := append([]byte(nil), b[:n]...)
				response[0] = 2
				for i := 22; i < 38; i++ {
					response[i] = 0
				}
				mac := hmac.New(md5.New, secret)
				_, _ = mac.Write(response)
				copy(response[22:], mac.Sum(nil))
				hash := md5.New()
				_, _ = hash.Write(response)
				_, _ = hash.Write(secret)
				copy(response[4:20], hash.Sum(nil))
				if corrupt {
					response[22] ^= 1
				}
				binary.BigEndian.PutUint16(response[2:4], uint16(n))
				_, _ = s.WriteTo(response, peer)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			e = ProbeStatus(ctx, s.LocalAddr().String(), secret)
			if (e == nil) == corrupt {
				t.Fatalf("error=%v", e)
			}
		})
	}
}
