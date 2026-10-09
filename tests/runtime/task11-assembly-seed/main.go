// Development-only preparation and separately authorized primitive execution.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"golang.org/x/sys/unix"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const cloudHelper = "/usr/local/libexec/task11-cloud-contract"
const cloudHelperSHA = "e6c0a5373ca718e17cf288f28095223c67dbfefa88461233ed1660ec2d5fd0d4"

func guestGuard() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("owned Linux root guest required")
	}
	raw, err := os.ReadFile("/etc/cloud8021x-task11-fixture")
	if err != nil || string(raw) != "synthetic-only-v1\n" {
		return errors.New("synthetic guest marker absent")
	}
	var stat unix.Stat_t
	if unix.Lstat("/etc/cloud8021x-task11-fixture", &stat) != nil || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("guest marker ownership rejected")
	}
	st, err := os.Lstat("/etc/cloud8021x-task11-fixture")
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe guest marker")
	}
	return nil
}
func readOriginal(root string) (map[string][]byte, error) {
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if len(out) >= 80 {
			return errors.New("original file count exceeded")
		}
		b, e := readPrivate(path)
		if e != nil {
			return e
		}
		out[rel] = b
		return nil
	})
	return out, err
}
func finalizeDirectory(control string, p plan, dry bool) error {
	if err := checkPrivateDirectory(control); err != nil {
		return err
	}
	for _, name := range []string{"enrollment.json", "stage.json", "primitive-api", "original-seed/assembly-input.json", "original-seed/api/remote-state.json", "original-seed/api/journal.jsonl", "original-seed/api/state.lock", "assembly-finalization.lock"} {
		if _, err := os.Lstat(filepath.Join(control, name)); !os.IsNotExist(err) {
			return errors.New("finalization requires unused, unenrolled private inputs")
		}
	}
	root := filepath.Join(control, "original-seed")
	files, err := readOriginal(root)
	if err != nil {
		return err
	}
	result, err := finalize(p, files)
	if err != nil {
		return err
	}
	if dry {
		return nil
	}
	if err = writeExclusive(filepath.Join(control, "assembly-finalization.lock"), []byte("exclusive-input-finalization-v1\n")); err != nil {
		return err
	}
	// The lock is deliberately permanent. Any partial write refuses future reuse.
	again, err := readOriginal(root)
	if err != nil {
		return err
	}
	before, _ := json.Marshal(files)
	after, _ := json.Marshal(again)
	if digest(before) != digest(after) {
		return errors.New("original inputs changed before finalization")
	}
	names := make([]string, 0, len(result.Original))
	for name := range result.Original {
		if _, original := files[name]; !original && name != "assembly-input.json" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(root, name)
		if err = mkdirPrivate(filepath.Dir(path)); err != nil {
			return err
		}
		if err = writeExclusive(path, result.Original[name]); err != nil {
			return err
		}
	}
	primitive := filepath.Join(control, "primitive-api")
	if err = os.Mkdir(primitive, 0700); err != nil {
		return err
	}
	names = nil
	for name := range result.Primitive {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err = writeExclusive(filepath.Join(primitive, name), result.Primitive[name]); err != nil {
			return err
		}
	}
	for _, name := range []string{"api/seed.json", "original-manifest.json"} {
		if err = replaceOriginal(filepath.Join(root, name), result.Original[name]); err != nil {
			return err
		}
	}
	return writeExclusive(filepath.Join(root, "assembly-input.json"), result.Original["assembly-input.json"])
}
func primitiveGuest(ctx context.Context, seedPin, inputPin, expectedPin string, dry bool) error {
	root := contract.ControlRoot + "/primitive-api"
	for _, pin := range []string{seedPin, inputPin, expectedPin} {
		if !contract.IsSHA(pin) {
			return errors.New("independent primitive byte pins required")
		}
	}
	seed, err := readPrivate(root + "/seed.json")
	if err != nil || digest(seed) != seedPin {
		return errors.New("primitive seed differs")
	}
	raw, err := readPrivate(root + "/driver-input.json")
	if err != nil || digest(raw) != inputPin {
		return errors.New("primitive driver input differs")
	}
	var p primitivePlan
	if domain.DecodeJSONStrict(raw, &p) != nil || p.SeedSHA256 != seedPin {
		return errors.New("primitive driver binding differs")
	}
	expected, err := projectPrimitive(p)
	if err != nil {
		return err
	}
	expectedBytes, _ := json.Marshal(expected)
	stored, err := readPrivate(root + "/expected.json")
	if err != nil || digest(stored) != expectedPin || digest(expectedBytes) != expectedPin {
		return errors.New("independent expected projection differs")
	}
	ca, err := readPrivate(root + "/ca.pem")
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return errors.New("primitive TLS CA invalid")
	}
	if err = pinnedHelper(); err != nil {
		return err
	}
	if dry {
		return nil
	}
	if err = writeExclusive(root+"/driver-attempt.lock", []byte("one-primitive-attempt-v1\n")); err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil || port != "443" || (host != "secretmanager.googleapis.com" && host != "fleet.task11.test" && host != "otlp.task11.test") {
			return nil, errors.New("unapproved primitive endpoint")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", "10.203.11.10:443")
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("primitive redirect refused") }}
	scenario := func(ctx context.Context, name string) error {
		_, e := helperCommand(ctx, "scenario", name, "--gate", "primitive-contract", "--command", primitiveCommand)
		return e
	}
	if err = drivePrimitive(ctx, p, client, scenario); err != nil {
		return err
	}
	result, err := helperCommand(ctx, "verify", "--gate", "primitive-contract", "--application-sha256", p.ApplicationSHA256, "--expected-sha256", expectedPin)
	if err != nil {
		return err
	}
	return writeExclusive(root+"/verified-result.json", result)
}
func main() {
	var debug, dry bool
	command := &cobra.Command{Use: "task11-assembly-seed", SilenceUsage: true, SilenceErrors: true, PersistentPreRun: func(*cobra.Command, []string) {
		if debug {
			logrus.SetLevel(logrus.DebugLevel)
		}
	}}
	command.PersistentFlags().BoolVar(&debug, "debug", false, "bounded diagnostic logging")
	command.PersistentFlags().BoolVar(&dry, "dry-run", false, "validate inputs without writing or making requests")
	command.AddCommand(&cobra.Command{Use: "finalize", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		if err := guestGuard(); err != nil {
			return err
		}
		raw, err := readPrivate(contract.ControlRoot + "/assembly-seed-plan.json")
		if err != nil {
			return err
		}
		var p plan
		if domain.DecodeJSONStrict(raw, &p) != nil {
			return errors.New("strict finalization plan required")
		}
		return finalizeDirectory(contract.ControlRoot, p, dry)
	}})
	var seedPin, inputPin, expectedPin string
	primitive := &cobra.Command{Use: "primitive", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := guestGuard(); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), time.Minute)
		defer cancel()
		return primitiveGuest(ctx, seedPin, inputPin, expectedPin, dry)
	}}
	primitive.Flags().StringVar(&seedPin, "seed-sha256", "", "reviewed primitive seed bytes")
	primitive.Flags().StringVar(&inputPin, "input-sha256", "", "independent primitive driver input bytes")
	primitive.Flags().StringVar(&expectedPin, "expected-sha256", "", "independent typed expected projection bytes")
	command.AddCommand(primitive)
	if err := command.Execute(); err != nil {
		logrus.WithField("operation", "assembly-seed").Error("development fixture operation refused")
		if debug {
			logrus.WithField("error_type", fmtErrorType(err)).Debug("bounded diagnostic")
		}
		os.Exit(1)
	}
}
func fmtErrorType(err error) string {
	if os.IsPermission(err) {
		return "permissions"
	}
	return "validation-or-execution"
}
