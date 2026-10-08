package host

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/freeradius/native"
	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
)

type RadiusBackend struct {
	releaseBarrier    func(context.Context) error
	CollectorAccounts *Accounts
	collectorStart    func(context.Context) error
	run               commandRunner
	quiescent         func() error
	caHealth          func(context.Context) error
	ECDNS, RSADNS     string
	CATrust           []byte
	status            func(context.Context, string, []byte) error
	readiness         func(context.Context, string, []byte, native.Readiness) error
	Companions        bool
	Local, Peer       string
	Secret            []byte
	Expected          native.Readiness
}

func (b *RadiusBackend) command(ctx context.Context, path string, args ...string) ([]byte, error) {
	if b.run != nil {
		return b.run(ctx, path, args...)
	}
	return execute(ctx, path, args...)
}
func (b *RadiusBackend) probeStatus(ctx context.Context, address string) error {
	if b.status != nil {
		return b.status(ctx, address, b.Secret)
	}
	return native.ProbeStatus(ctx, address, b.Secret)
}
func (b *RadiusBackend) probeReadiness(ctx context.Context, address string) error {
	if b.readiness != nil {
		return b.readiness(ctx, address, b.Secret, b.Expected)
	}
	return native.ProbeReadiness(ctx, address, b.Secret, b.Expected)
}
func (b *RadiusBackend) Running(ctx context.Context) (bool, error) {
	out, e := b.command(ctx, "/usr/bin/systemctl", "show", "freeradius.service", "--property=ActiveState", "--property=SubState", "--property=MainPID")
	if e != nil {
		return false, e
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(line, "=")
		fields[k] = v
	}
	if fields["ActiveState"] == "active" && fields["MainPID"] != "" && fields["MainPID"] != "0" {
		return true, nil
	}
	if fields["ActiveState"] == "inactive" && fields["SubState"] == "dead" && fields["MainPID"] == "0" {
		check := b.quiescent
		if check == nil {
			check = nativeListenersQuiescent
		}
		if e := check(); e != nil {
			return false, errors.New("native service inactive but authentication/accounting listeners not proven quiescent")
		}
		return false, nil
	}
	return false, errors.New("native service state is not proven stopped or running")
}
func (b *RadiusBackend) PeerReady(ctx context.Context) error {
	if e := b.probeStatus(ctx, net.JoinHostPort(b.Peer, "18121")); e != nil {
		return e
	}
	return b.probeReadiness(ctx, "http://"+net.JoinHostPort(b.Peer, "18122"))
}
func (b *RadiusBackend) Validate(ctx context.Context) error {
	if b.Companions {
		if e := ValidateInstalledUnits(ctx); e != nil {
			return e
		}
	}
	_, e := execute(ctx, "/usr/sbin/freeradius", "-d", "/etc/freeradius/3.0", "-XC")
	return e
}
func (b *RadiusBackend) Activate(ctx context.Context) error {
	if e := CheckRestart(ctx, b); e != nil {
		return e
	}
	active, e := b.Running(ctx)
	if e != nil {
		return e
	}
	if b.Companions {
		// Stop native listeners before replacing their synchronous policy dependency.
		// Otherwise a temporary REST failure can become Access-Reject rather than NAS
		// failover. The shared gate and authenticated peer check precede this stop.
		if active {
			if _, e = b.command(ctx, "/usr/bin/systemctl", "stop", "freeradius.service"); e != nil {
				return e
			}
			still, e := b.Running(ctx)
			if e != nil || still {
				return errors.New("native listener did not stop before policy replacement")
			}
		}
		if _, e = b.command(ctx, "/usr/bin/systemctl", "daemon-reload"); e != nil {
			return e
		}
		if _, e = b.command(ctx, "/usr/sbin/update-ca-certificates"); e != nil {
			return e
		}
		if _, e = b.command(ctx, "/usr/bin/systemctl", "restart", "cloud-8021x.service"); e != nil {
			return e
		}
		if e = b.waitPolicy(ctx); e != nil {
			return e
		}
		for _, unit := range []string{"step-ca.service", "step-ca-rsa.service"} {
			if _, e = b.command(ctx, "/usr/bin/systemctl", "restart", unit); e != nil {
				return e
			}
		}
		if e = b.waitCAs(ctx); e != nil {
			return e
		}
		if b.collectorStart != nil {
			if e = b.collectorStart(ctx); e != nil {
				return e
			}
		} else if b.CollectorAccounts != nil {
			if e = StartCollector(ctx, *b.CollectorAccounts); e != nil {
				return e
			}
		}
		if b.releaseBarrier != nil {
			if e = b.releaseBarrier(ctx); e != nil {
				return e
			}
		}
		_, e = b.command(ctx, "/usr/bin/systemctl", "start", "freeradius.service")
		return e
	}
	action := "start"
	if active {
		action = "restart"
	}
	_, e = b.command(ctx, "/usr/bin/systemctl", action, "freeradius.service")
	return e
}
func (b *RadiusBackend) waitPolicy(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		if e := b.probeReadiness(ctx, "http://"+net.JoinHostPort(b.Local, "18122")); e == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("local policy did not become ready; native listener remains stopped")
		case <-time.After(250 * time.Millisecond):
		}
	}
}
func (b *RadiusBackend) Healthy(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		if e := native.ProbeStatus(ctx, net.JoinHostPort(b.Local, "18121"), b.Secret); e == nil {
			return native.ProbeReadiness(ctx, "http://"+net.JoinHostPort(b.Local, "18122"), b.Secret, b.Expected)
		}
		select {
		case <-ctx.Done():
			return errors.New("native backend did not become ready")
		case <-time.After(250 * time.Millisecond):
		}
	}
}
func InstallMetadata(ctx context.Context, uid int) error {
	data, e := MetadataRules(uid)
	if e != nil {
		return e
	}
	if e = Write(File{Path: MetadataRulesFile, Data: data, Mode: 0600}); e != nil {
		return e
	}
	_, e = execute(ctx, "/usr/sbin/nft", "--file", MetadataRulesFile)
	return e
}

func ValidateInstalledUnits(ctx context.Context) error {
	_, e := execute(ctx, "/usr/sbin/visudo", "--check", "--file", "/etc/sudoers.d/cloud-8021x")
	return e
}
func EnableInstalledUnits(ctx context.Context) error {
	_, e := execute(ctx, "/usr/bin/systemctl", "enable", "cloud-8021x.service", "cloud-8021x-credentials.service", "cloud-8021x-metadata.service", "step-ca.service", "step-ca-rsa.service", "freeradius.service", "cloud-8021x-renew.timer", "datadog-agent-ddot.service", CollectorMount)
	return e
}

// An inactive systemd unit does not prove a legacy or orphaned native process is
// absent. Exclusive wildcard binds independently cover all configured IPv4
// authentication/accounting listeners. Held together, then closed before start.
func nativeListenersQuiescent() error {
	var sockets []*net.UDPConn
	defer func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
	}()
	for _, port := range []int{1812, 1813, 18121} {
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
		if err != nil {
			return err
		}
		sockets = append(sockets, socket)
	}
	return nil
}

func (b *RadiusBackend) waitCAs(ctx context.Context) error {
	if b.caHealth != nil {
		return b.caHealth(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		ec := stepca.ProbeHealth(ctx, "127.0.0.1:8443", b.ECDNS, b.CATrust)
		rsa := stepca.ProbeHealth(ctx, "127.0.0.1:8444", b.RSADNS, b.CATrust)
		if ec == nil && rsa == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("local CA readiness unavailable; native remains stopped")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Quiesce is a fixed native-only stop behind the same actual peer gate. Used
// before package changes and before restoring a policy dependency on rollback.
func (b *RadiusBackend) Quiesce(ctx context.Context) error {
	if err := CheckRestart(ctx, b); err != nil {
		return err
	}
	active, err := b.Running(ctx)
	if err != nil {
		return err
	}
	if active {
		if _, err = b.command(ctx, "/usr/bin/systemctl", "stop", "freeradius.service"); err != nil {
			return err
		}
	}
	active, err = b.Running(ctx)
	if err != nil || active {
		return errors.New("native listeners did not quiesce")
	}
	return nil
}

// PackageBarrier owns a runtime-only mask so audited package maintainer scripts
// cannot bring native listeners back before the policy dependency is ready.
func (b *RadiusBackend) PackageBarrier(ctx context.Context) error {
	state, err := b.command(ctx, "/usr/bin/systemctl", "show", "freeradius.service", "--property=LoadState", "--value")
	if err != nil || (strings.TrimSpace(string(state)) != "loaded" && strings.TrimSpace(string(state)) != "not-found") {
		return errors.New("native unit mask ownership is not known")
	}
	if err = b.Quiesce(ctx); err != nil {
		return err
	}
	_, err = b.command(ctx, "/usr/bin/systemctl", "mask", "--runtime", "freeradius.service")
	return err
}
func (b *RadiusBackend) RemovePackageBarrier(ctx context.Context) error {
	_, err := b.command(ctx, "/usr/bin/systemctl", "unmask", "--runtime", "freeradius.service")
	return err
}

// stopOwnedStart is only used while rolling back this transaction's own start
// from a positively stopped original state, never for an adopted active node.
func (b *RadiusBackend) stopOwnedStart(ctx context.Context) error {
	if _, err := b.command(ctx, "/usr/bin/systemctl", "stop", "freeradius.service"); err != nil {
		return err
	}
	active, err := b.Running(ctx)
	if err != nil || active {
		return errors.New("owned native start did not stop")
	}
	return nil
}
func (b *RadiusBackend) stopCompanions(ctx context.Context) error {
	if !b.Companions {
		return nil
	}
	for _, unit := range []string{"cloud-8021x.service", "step-ca.service", "step-ca-rsa.service", "datadog-agent-ddot.service"} {
		if _, err := b.command(ctx, "/usr/bin/systemctl", "stop", unit); err != nil {
			return err
		}
	}
	return nil
}
