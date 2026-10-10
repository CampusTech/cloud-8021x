package host

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This runs only in the explicitly labelled disposable Linux fixture launched
// by scripts/test_bootstrap_isolation.sh, never against host networking.
func TestInstalledMetadataIsolation(t *testing.T) {
	if os.Getenv("C8021X_ISOLATION_FIXTURE") != "task8" {
		t.Skip("owned disposable Linux namespace required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture must start as root")
	}
	run := func(name string, args ...string) {
		t.Helper()
		if out, e := exec.Command(name, args...).CombinedOutput(); e != nil {
			t.Fatalf("fixture command %s failed: %s (%v)", name, out, e)
		}
	}
	run("ip", "addr", "add", "169.254.169.254/32", "dev", "lo")
	run("ip", "-6", "addr", "add", "fd20:ce::254/128", "dev", "lo")
	for _, address := range []string{"169.254.169.254", "fd20:ce::254"} {
		for _, port := range []string{"53", "80", "443"} {
			listener, e := net.Listen("tcp", net.JoinHostPort(address, port))
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { _ = listener.Close() })
			go func() {
				for {
					c, e := listener.Accept()
					if e != nil {
						return
					}
					go func() {
						defer func() { _ = c.Close() }()
						_ = c.SetDeadline(time.Now().Add(time.Second))
						b := make([]byte, 32)
						n, _ := c.Read(b)
						_, _ = c.Write(b[:n])
					}()
				}
			}()
		}
		socket, e := net.ListenPacket("udp", net.JoinHostPort(address, "53"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = socket.Close() })
		go func() {
			b := make([]byte, 512)
			for {
				n, peer, e := socket.ReadFrom(b)
				if e != nil {
					return
				}
				_, _ = socket.WriteTo(b[:n], peer)
			}
		}()
	}
	hosts, e := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	_, e = hosts.WriteString("\n169.254.169.254 metadata.google.internal metadata.goog\n")
	_ = hosts.Close()
	if e != nil {
		t.Fatal(e)
	}
	rules, e := MetadataRules(1042)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("/tmp/task8-metadata.nft", rules, 0600); e != nil {
		t.Fatal(e)
	}
	run("nft", "-f", "/tmp/task8-metadata.nft")
	run("nft", "-f", "/tmp/task8-metadata.nft")
	// Actual root traffic still works; the daemon UID receives DNS only.
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, uid := range []string{"0", "1042"} {
		cmd := exec.Command("setpriv", "--reuid="+uid, "--regid="+uid, "--clear-groups", "--bounding-set=-all", binary, "-test.run=^TestMetadataChild$", "-test.v")
		cmd.Env = append(os.Environ(), "C8021X_METADATA_CHILD="+uid)
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("UID%s installed proof: %s (%v)", uid, out, e)
		}
	}
}
func TestMetadataChild(t *testing.T) {
	who := os.Getenv("C8021X_METADATA_CHILD")
	if who == "" {
		t.Skip("subprocess only")
	}
	for _, host := range []string{"169.254.169.254", "metadata.google.internal", "metadata.goog", "fd20:ce::254", "::ffff:169.254.169.254"} {
		for _, port := range []string{"53", "80", "443"} {
			protocols := []string{"tcp"}
			if port == "53" {
				protocols = append(protocols, "udp")
			}
			for _, protocol := range protocols {
				address := net.JoinHostPort(host, port)
				c, e := net.DialTimeout(protocol, address, time.Second)
				ok := false
				if e == nil {
					_ = c.SetDeadline(time.Now().Add(time.Second))
					_, e = c.Write([]byte("dns-transport-proof"))
					if e == nil {
						b := make([]byte, 64)
						n, err := c.Read(b)
						ok = err == nil && bytes.Equal(b[:n], []byte("dns-transport-proof"))
					}
					_ = c.Close()
				}
				want := who == "0" || port == "53"
				if ok != want {
					t.Errorf("%s %s reachable=%t want=%t", protocol, address, ok, want)
				}
			}
		}
	}
	if who != "0" {
		status, e := os.ReadFile("/proc/self/status")
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "CapEff:") && strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")) != "0000000000000000" {
				t.Fatal("daemon has effective capabilities")
			}
		}
		if e = exec.Command("nft", "flush", "ruleset").Run(); e == nil {
			t.Fatal("daemon changed metadata rules")
		}
		fmt.Println("daemon metadata HTTP/HTTPS denied; UDP/TCP DNS available; capabilities absent")
	}
}
