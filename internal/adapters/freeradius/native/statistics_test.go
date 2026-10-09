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

func statsAttribute(id byte, value uint32) []byte {
	raw := []byte{26, 12, 0, 0, 44, 80, id, 6, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(raw[8:], value)
	return raw
}
func TestNativeStatisticsRequestsAuthenticatedBoundedCounters(t *testing.T) {
	for _, kind := range []string{"valid", "missing", "tampered", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			socket, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = socket.Close() }()
			secret := []byte("fixture-health-secret-32-bytes-long")
			observed := make(chan bool, 1)
			go func() {
				request := make([]byte, 4096)
				n, peer, e := socket.ReadFrom(request)
				if e != nil {
					return
				}
				request = request[:n]
				requested := false
				for i := 20; i+2 <= n; i += int(request[i+1]) {
					if request[i+1] < 2 {
						break
					}
					if request[i] == 26 && request[i+1] == 12 && binary.BigEndian.Uint32(request[i+2:i+6]) == 11344 && request[i+6] == 127 && binary.BigEndian.Uint32(request[i+8:i+12]) == 19 {
						requested = true
					}
				}
				observed <- requested
				response := append([]byte(nil), request[:20]...)
				response[0] = 2
				if kind != "missing" {
					response = append(response, statsAttribute(128, 42)...)
					response = append(response, statsAttribute(164, 3)...)
				}
				if kind == "duplicate" {
					response = append(response, statsAttribute(128, 99)...)
				}
				response = append(response, 80, 18)
				response = append(response, make([]byte, 16)...)
				binary.BigEndian.PutUint16(response[2:4], uint16(len(response)))
				mac := hmac.New(md5.New, secret)
				_, _ = mac.Write(response)
				copy(response[len(response)-16:], mac.Sum(nil))
				hash := md5.New()
				_, _ = hash.Write(response)
				_, _ = hash.Write(secret)
				copy(response[4:20], hash.Sum(nil))
				if kind == "tampered" {
					response[28] ^= 1
				}
				_, _ = socket.WriteTo(response, peer)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			stats, err := ObserveStatistics(ctx, socket.LocalAddr().String(), secret)
			if !<-observed {
				t.Error("native observation never requested authentication/accounting/internal statistics")
			}
			if kind == "tampered" || kind == "duplicate" {
				if err == nil {
					t.Fatal("untrusted statistics accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "missing" {
				if len(stats) != 0 {
					t.Fatal("absent stats invented zero")
				}
				return
			}
			if len(stats) != 2 || stats["total_access_requests"] != 42 || stats["queue_len_auth"] != 3 {
				t.Fatal("actual counters/queue lost", stats)
			}
		})
	}
}
