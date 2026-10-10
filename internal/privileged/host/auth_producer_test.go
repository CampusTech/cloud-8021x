package host

import (
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/templates/systemd"
)

func TestNativeProducerAcceptsCurrentProtectedService(t *testing.T) {
	files, err := systemd.Render()
	if err != nil {
		t.Fatal(err)
	}
	var command string
	for _, line := range strings.Split(string(files["/etc/systemd/system/freeradius.service.d/cloud-8021x.conf"]), "\n") {
		if value, ok := strings.CutPrefix(line, "ExecStart="); ok && value != "" {
			command = value
		}
	}
	if command == "" {
		t.Fatal("protected service command unavailable")
	}
	args := strings.Join(strings.Fields(command), "\x00") + "\x00"
	expected := writerPID{PID: 421, Start: 98765}
	got, err := selectNativeProducer(expected.PID, []writerProcess{{PID: 422, Start: 111, Args: args}, {PID: expected.PID, Start: expected.Start, Args: args}})
	if err != nil {
		t.Fatalf("current protected service producer rejected: %v", err)
	}
	if got != expected {
		t.Fatalf("producer PID/start changed: got %+v, want %+v", got, expected)
	}
}

func TestNativeProducerRejectsDifferentServiceIdentity(t *testing.T) {
	for name, args := range map[string][]string{
		"implicit vendor config":  {"/usr/sbin/freeradius", "-f"},
		"foreign executable":      {"/tmp/freeradius", "-d", radiusDirectory, "-f"},
		"relative executable":     {"freeradius", "-d", radiusDirectory, "-f"},
		"interpreter wrapper":     {"/bin/sh", "/usr/sbin/freeradius", "-d", radiusDirectory, "-f"},
		"vendor default config":   {"/usr/sbin/freeradius", "-d", "/etc/freeradius", "-f"},
		"different config":        {"/usr/sbin/freeradius", "-d", "/tmp/radius", "-f"},
		"extra flag":              {"/usr/sbin/freeradius", "-d", radiusDirectory, "-f", "-X"},
		"configuration validator": {"/usr/sbin/freeradius", "-d", radiusDirectory, "-XC"},
		"daemonizing process":     {"/usr/sbin/freeradius", "-d", radiusDirectory},
		"empty argument":          {"/usr/sbin/freeradius", "-d", radiusDirectory, "-f", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := selectNativeProducer(421, []writerProcess{{PID: 421, Start: 98765, Args: strings.Join(args, "\x00") + "\x00"}}); err == nil {
				t.Fatal("different process accepted as protected producer")
			}
		})
	}
	if _, err := selectNativeProducer(421, []writerProcess{{PID: 422, Start: 98765, Args: "/usr/sbin/freeradius\x00-d\x00/etc/freeradius/3.0\x00-f\x00"}}); err == nil {
		t.Fatal("unrelated PID accepted")
	}
}
