//go:build linux

package native

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstalledNativeStatistics(t *testing.T) {
	if os.Getenv("C8021X_NATIVE_STATS_FIXTURE") != "task10" {
		t.Skip("owned installed native stats fixture required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("disposable container required")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("h", 32)
	cfg := `prefix = /usr
libdir = /usr/lib/freeradius
raddbdir = ` + dir + `
logdir = ` + dir + `
run_dir = ` + dir + `
radacctdir = ` + dir + `
name = freeradius
max_request_time = 10
security {
 status_server = no
}
log {
 destination = stdout
}
modules {
 always ok {
  rcode = ok
 }
}
client local {
 ipaddr = 127.0.0.1
 secret = ` + secret + `
 require_message_authenticator = yes
}
server fixture {
 listen {
  type = auth
  ipaddr = 127.0.0.1
  port = 19120
 }
 authorize {
  update control {
   Auth-Type := Accept
  }
 }
}
server health {
 listen {
  type = status
  ipaddr = 127.0.0.1
  port = 19121
 }
 authorize {
  ok
 }
}
`
	for name, data := range map[string]string{"radiusd.conf": cfg, "dictionary": "$INCLUDE /usr/share/freeradius/dictionary\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	var log bytes.Buffer
	cmd := exec.Command("/usr/sbin/freeradius", "-d", dir, "-f")
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ctx := context.Background()
	var before map[string]uint32
	var err error
	for range 50 {
		before, err = ObserveStatistics(ctx, "127.0.0.1:19121", []byte(secret))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("actual native status unavailable", err, log.String())
	}
	for _, name := range []string{"total_access_requests", "total_access_challenges", "total_auth_duplicate_requests", "total_auth_malformed_requests", "total_auth_invalid_requests", "total_auth_dropped_requests", "total_acct_requests", "total_acct_responses", "queue_len_internal", "queue_len_auth", "queue_len_acct", "start_time"} {
		if _, ok := before[name]; !ok {
			t.Fatal("shipped native did not return required statistic", name, before)
		}
	}
	for id := byte(1); id <= 2; id++ {
		conn, e := net.Dial("udp", "127.0.0.1:19120")
		if e != nil {
			t.Fatal(e)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		packet := make([]byte, 38)
		packet[0] = 1
		packet[1] = id
		packet[4] = id
		binary.BigEndian.PutUint16(packet[2:4], 38)
		packet[20], packet[21] = 80, 18
		mac := hmac.New(md5.New, []byte(secret))
		_, _ = mac.Write(packet)
		copy(packet[22:], mac.Sum(nil))
		_, e = conn.Write(packet)
		if e != nil {
			t.Fatal(e)
		}
		reply := make([]byte, 4096)
		n, e := conn.Read(reply)
		_ = conn.Close()
		if e != nil || n < 20 || reply[0] != 2 {
			t.Fatal("native fixture packet not accepted", e)
		}
	}
	after, err := ObserveStatistics(ctx, "127.0.0.1:19121", []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if after["total_access_requests"]-before["total_access_requests"] != 2 {
		t.Fatal("native request count not grounded in actual packets", before, after)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	cmd = exec.Command("/usr/sbin/freeradius", "-d", dir, "-f")
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var restarted map[string]uint32
	for range 50 {
		restarted, err = ObserveStatistics(ctx, "127.0.0.1:19121", []byte(secret))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || restarted["total_access_requests"] != 0 {
		t.Fatal("actual native restart did not reset source counter", restarted, err)
	}
	raw, _ := json.Marshal(after)
	t.Log(string(raw))
	if path := os.Getenv("C8021X_NATIVE_STATS_OUTPUT"); path != "" {
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
