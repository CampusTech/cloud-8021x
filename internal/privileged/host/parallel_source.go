package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
)

const parallelSourceKey = transactionRoot + "/parallel-source.key"

// ParallelSourceKey creates only this old host's root-private receipt signer.
// Its public pin must reach the reviewed destination configuration through the
// operator's authenticated SSH/IAP channel before any handoff is accepted.
func ParallelSourceKey() (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("root source identity required")
	}
	if err := protectedDirectory(transactionRoot, 0, 0, 0700); err != nil {
		return "", err
	}
	key, err := readPrivateCache(parallelSourceKey, ed25519.PrivateKeySize)
	if errors.Is(err, os.ErrNotExist) {
		_, generated, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return "", e
		}
		if e = privateWrite(parallelSourceKey, generated, 0600); e != nil {
			return "", e
		}
		if e = syncWriterDirectory(transactionRoot); e != nil {
			return "", e
		}
		key = generated
	} else if err != nil {
		return "", err
	}
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("invalid original source identity")
	}
	return hex.EncodeToString(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)), nil
}
func parallelSourcePin(c config.Config) (ed25519.PublicKey, error) {
	pin := c.Deployment.SourcePrimaryKey
	if c.InstanceID == "radius-secondary" {
		pin = c.Deployment.SourceSecondaryKey
	}
	key, err := hex.DecodeString(pin)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("reviewed original source public key pin required")
	}
	return ed25519.PublicKey(key), nil
}
func VerifyParallelSource(raw []byte, c config.Config, release string, now time.Time) (adoption.Authorization, error) {
	binding, err := adoption.ExpectedBinding(c, release)
	if err != nil {
		return adoption.Authorization{}, err
	}
	key, err := parallelSourcePin(c)
	if err != nil {
		return adoption.Authorization{}, err
	}
	return adoption.Verify(raw, key, binding, now)
}

// CaptureParallelSource has no native stop, package, SQL, CA, network/firewall or
// Fleet call. The already verified standalone binary uses only fixed old paths.
// Scheduler fencing is physical and persistent; absence on green is irrelevant.
func CaptureParallelSource(ctx context.Context, c config.Config, release string) ([]byte, error) {
	return captureParallelSource(ctx, c, release, execute)
}
func captureParallelSource(ctx context.Context, c config.Config, release string, run commandRunner) ([]byte, error) {
	if err := c.ValidateHandoffPins(); err != nil {
		return nil, err
	}
	binding, err := adoption.ExpectedBinding(c, release)
	if err != nil {
		return nil, err
	}
	hostname, err := os.Hostname()
	if err != nil || strings.Split(hostname, ".")[0] != binding.SourceInstance {
		return nil, errors.New("capture must run on the original physical source instance")
	}
	pin, err := parallelSourcePin(c)
	if err != nil {
		return nil, err
	}
	key, err := readPrivateCache(parallelSourceKey, ed25519.PrivateKeySize)
	if err != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.PrivateKey(key).Public().(ed25519.PublicKey), pin) {
		return nil, errors.New("source signing key differs from reviewed pin")
	}
	unlock, err := AcquireWriterOperation()
	if err != nil {
		return nil, err
	}
	defer unlock()
	fence, err := fenceLegacyWriters(ctx, c.StateTransition, c.InstanceID, binding.ConfigSHA256, run, legacyProcessesQuiescent)
	if err != nil {
		return nil, err
	}
	uid, _, err := identity("freerad")
	if err != nil {
		return nil, err
	}
	policy, err := readLegacyStateComponent("policy", uid)
	if err != nil || policy == nil {
		return nil, errors.New("original policy authorization unavailable")
	}
	certs, err := readLegacyStateComponent("certificates", uid)
	if err != nil || certs == nil {
		return nil, errors.New("original certificate command provenance unavailable")
	}
	class, err := legacyClassSnapshot()
	if err != nil || !class.Exists || len(class.Data) < 32 {
		return nil, errors.New("original Class key unavailable")
	}
	guard, err := snapshotState(File{Path: legacyDowngradeGuard})
	if err != nil {
		return nil, err
	}
	sourceConfig, err := installedHash("/etc/freeradius/3.0/radiusd.conf", 4<<20)
	if err != nil {
		return nil, err
	}
	if _, err = validateAdoptionSnapshot(policy.Data, "fingerprint", guard.Exists); err != nil {
		return nil, err
	}
	// Reprove the same masks/process/lock lineage after the bounded reads.
	if _, err = fenceLegacyWriters(ctx, c.StateTransition, c.InstanceID, binding.ConfigSHA256, run, legacyProcessesQuiescent); err != nil {
		return nil, err
	}
	native := &adoption.NativeIdentity{}
	for path, dest := range map[string]*[]byte{
		"/etc/acme-authz-webhook/server.crt":            &native.WebhookCertificate,
		"/etc/acme-authz-webhook/server.key":            &native.WebhookKey,
		"/etc/step-ca/config/ca.json":                   &native.ECConfig,
		"/etc/step-ca-rsa/config/ca.json":               &native.RSAConfig,
		"/etc/step-ca/templates/x509/wifi-acme.tpl":     &native.ECTemplate,
		"/etc/step-ca-rsa/templates/x509/wifi-scep.tpl": &native.RSATemplate,
	} {
		f, e := rootFile(path, 4<<20)
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(f)
		_ = f.Close()
		if e != nil {
			return nil, e
		}
		*dest = data
	}
	var trust []byte
	for _, path := range []string{"/etc/step-ca/certs/intermediate_ca.crt", "/etc/step-ca/certs/root_ca.crt", "/etc/step-ca-rsa/certs/intermediate_ca.crt", "/etc/step-ca-rsa/certs/root_ca.crt"} {
		f, e := rootFile(path, 1<<20)
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(f)
		_ = f.Close()
		if e != nil {
			return nil, e
		}
		trust = append(trust, data...)
	}
	doc := adoption.Authorization{Native: native, Binding: binding, CapturedAt: time.Now().UTC(), FenceSHA256: fence, SourceConfigSHA256: sourceConfig, ClassSHA256: digestBytes(class.Data), TrustSHA256: digestBytes(trust), FingerprintEnforced: guard.Exists, Policy: policy.Data, Certificates: certs.Data}
	encoded, err := adoption.Sign(doc, ed25519.PrivateKey(key))
	if err != nil {
		return nil, err
	}
	path := filepath.Join(transactionRoot, "parallel-"+c.InstanceID+".json")
	if err = Write(File{Path: path, Data: encoded, Mode: 0600}); err != nil {
		return nil, err
	}
	return encoded, nil
}
func ReadParallelSource(c config.Config, release string) ([]byte, adoption.Authorization, error) {
	// Operator transfers the signed output over authenticated root-only transport
	// into this one fixed slot. Neither a filename flag nor inline JSON is accepted.
	raw, err := readPrivateCache(ArtifactDirectory+"/parallel-"+c.InstanceID+".json", adoption.MaxBytes)
	if err != nil {
		return nil, adoption.Authorization{}, err
	}
	doc, err := VerifyParallelSource(raw, c, release, time.Now())
	return raw, doc, err
}

// VerifyParallelExecutable binds the actual executing standalone/installed
// helper, rather than merely trusting the digest written in a release manifest.
func VerifyParallelExecutable(release string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	actual, err := installedHash(executable, 256<<20)
	if err != nil || actual != release {
		return errors.New("executing parallel helper differs from reviewed release")
	}
	return nil
}
