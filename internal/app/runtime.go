package app

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/identity"
	"github.com/CampusTech/cloud-8021x/internal/network"
	"golang.org/x/sys/unix"
)

const privilegedConfigFile = "/etc/cloud-8021x/config.yaml"

type VerifiedLeafOptions struct {
	CertificateFile string
	SessionToken    string
}

func (o VerifiedLeafOptions) Validate() error {
	if !filepath.IsAbs(o.CertificateFile) || filepath.Clean(o.CertificateFile) != o.CertificateFile || strings.ContainsAny(o.CertificateFile, "\x00\r\n") || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(o.SessionToken) {
		return errors.New("verify-leaf requires a clean absolute certificate filename and a 64-lowercase-hex server session token")
	}
	return nil
}

type RuntimeServices struct{ SourceDependencies SourceDependencies }

func NewRuntimeServices() *RuntimeServices { return &RuntimeServices{} }

// Later orchestration tasks register the remaining concrete operations. Unimplemented
// operations remain explicit errors; verify-leaf is already a real executable path.
func (services *RuntimeServices) Run(ctx context.Context, op Operation, cfg config.Config, o RunOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if op == OperationSourcesApply {
		return applySources(ctx, o, services.SourceDependencies)
	}
	if op == OperationSitesSync {
		service, err := NetworkServiceFromConfig(cfg, new(network.Store), o.DryRun, nil)
		if err != nil {
			return err
		}
		service.Output = o.Output
		return service.Sync(ctx, o.DryRun)
	}
	if op == OperationInventorySync {
		service, cleanup, err := InventoryServiceFromConfig(ctx, cfg, new(domain.SnapshotStore), o.DryRun, nil)
		if err != nil {
			return err
		}
		defer cleanup()
		service.Logger = o.Logger
		if err = service.Sync(ctx, o.DryRun); err != nil {
			return err
		}
		if o.Output != nil {
			_, err = fmt.Fprintln(o.Output, "Inventory sync completed.")
		}
		return err
	}
	if op != OperationRadiusVerifyLeaf {
		return fmt.Errorf("%s: %w", op, ErrUnsupported)
	}
	return verifyLeaf(ctx, cfg, o)
}
func verifyLeaf(ctx context.Context, cfg config.Config, o RunOptions) error {
	if !o.DryRun || os.Geteuid() == 0 {
		if os.Geteuid() != 0 {
			return errors.New("verify-leaf mutation requires the constrained privileged TLS hook")
		}
		if o.ConfigFile != privilegedConfigFile {
			return errors.New("privileged verify-leaf requires the fixed protected application configuration")
		}
		trusted, err := readProtectedHookConfig(o.ConfigFile)
		if err != nil {
			return err
		}
		cfg = trusted
	}

	if o.VerifiedLeaf == nil {
		return errors.New("missing verified leaf hook inputs")
	}
	input := *o.VerifiedLeaf
	if err := input.Validate(); err != nil {
		return err
	}
	if filepath.Dir(input.CertificateFile) != cfg.Backends.RadiusVerifyLeafDir {
		return errors.New("verified leaf filename must be directly inside the configured fixed FreeRADIUS leaf directory")
	}
	if cfg.Policy.IdentityMode != "fingerprint" {
		return errors.New("verified leaf handoff requires fingerprint identity mode")
	}
	leafUID := os.Geteuid()
	if leafUID == 0 {
		producer, err := user.Lookup("freerad")
		if err != nil {
			return errors.New("fixed FreeRADIUS leaf producer account unavailable")
		}
		leafUID, err = strconv.Atoi(producer.Uid)
		if err != nil || leafUID <= 0 {
			return errors.New("invalid fixed FreeRADIUS leaf producer account")
		}
	}
	directory, err := identity.OpenLeafDirectory(cfg.Backends.RadiusVerifyLeafDir, leafUID)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	data, err := directory.Read(filepath.Base(input.CertificateFile))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return errors.New("verified leaf is not a parsed public X.509 certificate")
	}
	var attestation *identity.Attestation
	if cfg.Policy.AttestedACME.Enabled {
		issuer, err := identity.ReadLeaf(cfg.Policy.AttestedACME.IssuerFile)
		if err != nil {
			return errors.New("pinned attested issuer unavailable")
		}
		attestation = &identity.Attestation{IssuerPEM: issuer, Provisioner: cfg.Policy.AttestedACME.Provisioner}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.DryRun {
		if err := identity.CheckDowngradeGuard(cfg.Paths.DowngradeGuardFile, true, true); err != nil {
			return err
		}
		if o.Output != nil {
			_, err = fmt.Fprintln(o.Output, "Verified leaf handoff inputs valid; no handoff or guard written.")
		}
		return err
	}

	owner, err := user.Lookup(cfg.RuntimeUser)
	if err != nil {
		return errors.New("dedicated daemon account unavailable")
	}
	uid, err := strconv.Atoi(owner.Uid)
	if err != nil || uid == 0 {
		return errors.New("invalid dedicated daemon account")
	}
	if err := identity.CheckDowngradeGuard(cfg.Paths.DowngradeGuardFile, true, false); err != nil {
		return err
	}
	h := identity.Handoff{Directory: cfg.Paths.HandoffDir, MaxAge: cfg.Policy.HandoffMaxAge, OwnerUID: &uid}
	if err := h.RecordPEM(data, input.SessionToken, attestation, time.Now()); err != nil {
		return err
	}
	if o.Logger != nil {
		o.Logger.WithField("operation", OperationRadiusVerifyLeaf).Debug("TLS leaf handoff created")
	}
	return nil
}

// Only the fixed-path root hook calls this; configuration is decoded again from
// the protected descriptor so command-line/config injection cannot select root actions.
func readProtectedHookConfig(path string) (config.Config, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return config.Config{}, errors.New("protected hook configuration unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0022 != 0 {
		return config.Config{}, errors.New("hook configuration must be a root-owned, non-writable regular file")
	}
	return config.Decode(f)
}
