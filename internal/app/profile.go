package app

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/CampusTech/cloud-8021x/internal/webhook/challenge"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"howett.net/plist"
)

type profileOptions struct {
	Identity, Provisioner, SSID, ServerDNS, SCEPURL, CAFile, KeyFile, Output, FleetOutput string
	TTL                                                                                   time.Duration
}

func profileCommand(options *RunOptions) *cobra.Command {
	var o profileOptions
	cmd := &cobra.Command{Use: "byod-profile", Short: "Generate an optional private per-device SCEP profile without delivery", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := cmd.Context().Err(); err != nil {
			return err
		}
		for _, s := range []string{o.Identity, o.Provisioner, o.ServerDNS} {
			if s == "" || s != strings.TrimSpace(s) || strings.ContainsAny(s, "\x00\r\n") {
				return errors.New("exact identity, provisioner and server name required")
			}
		}
		if strings.HasSuffix(o.Identity, " Campus WiFi") || len(o.Identity) > 1024 || len(o.Provisioner) > 256 || len(o.SSID) == 0 || len(o.SSID) > 32 {
			return errors.New("invalid profile identity or SSID")
		}
		u, e := url.Parse(o.SCEPURL)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.TrimSuffix(u.EscapedPath(), "/") != "/scep/"+url.PathEscape(o.Provisioner) {
			return errors.New("direct HTTPS SCEP provisioner endpoint required")
		}
		if o.TTL < time.Second || o.TTL > 24*time.Hour || o.TTL%time.Second != 0 {
			return errors.New("challenge TTL requires whole seconds up to 24h")
		}
		paths := []string{o.Output}
		if o.FleetOutput != "" {
			paths = append(paths, o.FleetOutput)
		}
		used := map[string]bool{}
		for _, path := range paths {
			abs, e := filepath.Abs(path)
			if e != nil || path == "" || used[abs] {
				return errors.New("distinct new output paths required")
			}
			used[abs] = true
			if _, e = os.Lstat(path); !os.IsNotExist(e) {
				return errors.New("output already exists or is inaccessible")
			}
			parent, e := os.Stat(filepath.Dir(path))
			if e != nil || !parent.IsDir() {
				return errors.New("output directory unavailable")
			}
		}
		key, e := readInventoryFile(o.KeyFile, true, 4096)
		if e != nil {
			return e
		}
		key = bytes.TrimSpace(key)
		if len(key) < 32 {
			return errors.New("challenge signing key too short")
		}
		ca, e := os.ReadFile(o.CAFile)
		if e != nil {
			return errors.New("profile CA unavailable")
		}
		if block, rest := pem.Decode(ca); block != nil {
			if block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
				return errors.New("exactly one CA certificate required")
			}
			ca = block.Bytes
		}
		cert, e := x509.ParseCertificate(ca)
		if e != nil || !cert.IsCA {
			return errors.New("valid CA certificate required")
		}
		if _, e = profileBytes(o, ca, "dry-run"); e != nil {
			return e
		}
		if options.DryRun {
			_, e = fmt.Fprintln(cmd.OutOrStdout(), "Profile inputs valid; no challenge issued or files written.")
			return e
		}
		token, e := challenge.Issue(key, o.Identity, o.Provisioner, time.Now(), o.TTL)
		if e != nil {
			return e
		}
		profile, e := profileBytes(o, ca, token)
		if e != nil {
			return e
		}
		outputs := [][]byte{profile}
		if o.FleetOutput != "" {
			command, e := plist.Marshal(map[string]any{"CommandUUID": uuid.NewString(), "Command": map[string]any{"RequestType": "InstallProfile", "Payload": profile}}, plist.XMLFormat)
			if e != nil {
				return e
			}
			body, e := json.Marshal(map[string]any{"host_uuids": []string{o.Identity}, "command": base64.StdEncoding.EncodeToString(command)})
			if e != nil {
				return e
			}
			outputs = append(outputs, append(body, '\n'))
		}
		created := []string{}
		complete := false
		defer func() {
			if !complete {
				for _, p := range created {
					_ = os.Remove(p)
				}
			}
		}()
		for i, path := range paths {
			if e = cmd.Context().Err(); e != nil {
				return e
			}
			f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return errors.New("private output creation failed")
			}
			created = append(created, path)
			_, e = f.Write(outputs[i])
			if e == nil {
				e = f.Sync()
			}
			e = errors.Join(e, f.Close())
			if e != nil {
				return errors.New("private output write failed")
			}
		}
		complete = true
		_, e = fmt.Fprintln(cmd.OutOrStdout(), "Private profile written; deliver before the challenge expires. No API calls made.")
		return e
	}}
	f := cmd.Flags()
	f.StringVar(&o.Identity, "identity", "", "Exact trusted inventory identity")
	f.StringVar(&o.Provisioner, "provisioner", "", "Exact SCEP provisioner")
	f.StringVar(&o.SCEPURL, "scep-url", "", "Direct HTTPS SCEP URL")
	f.StringVar(&o.SSID, "ssid", "", "Wi-Fi SSID")
	f.StringVar(&o.ServerDNS, "radius-server-name", "", "Pinned RADIUS server DNS")
	f.StringVar(&o.CAFile, "radius-ca-cert", "", "Public RADIUS CA PEM or DER")
	f.StringVar(&o.KeyFile, "signing-key-file", "", "Private challenge signing key file")
	f.StringVar(&o.Output, "out", "", "New private mobileconfig output")
	f.StringVar(&o.FleetOutput, "fleet-command-out", "", "Optional new Fleet command JSON file; never submits")
	f.DurationVar(&o.TTL, "ttl", 15*time.Minute, "Whole-second enrollment lifetime, at most 24h")
	return cmd
}

// Python json.dumps default spacing/ensure_ascii is the deployed UUID namespace
// contract. Keep it independent of Go JSON's HTML escaping and Unicode choices.
func profileNamespace(o profileOptions) uuid.UUID {
	quote := func(s string) string {
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"', '\\':
				b.WriteByte('\\')
				b.WriteRune(r)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				if r < 32 || r >= 127 {
					if r > 0xffff {
						a, z := utf16.EncodeRune(r)
						fmt.Fprintf(&b, `\u%04x\u%04x`, a, z)
					} else {
						fmt.Fprintf(&b, `\u%04x`, r)
					}
				} else {
					b.WriteRune(r)
				}
			}
		}
		b.WriteByte('"')
		return b.String()
	}
	values := []string{"cloud-8021x/byod", o.Identity, o.Provisioner, o.SSID}
	for i := range values {
		values[i] = quote(values[i])
	}
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("["+strings.Join(values, ", ")+"]"))
}
func profileBytes(o profileOptions, ca []byte, challenge string) ([]byte, error) {
	ns := profileNamespace(o)
	payload := func(kind, role, display string) map[string]any {
		id := strings.ToUpper(uuid.NewSHA1(ns, []byte(role)).String())
		return map[string]any{"PayloadType": kind, "PayloadVersion": 1, "PayloadIdentifier": "org.cloud8021x.byod." + id, "PayloadUUID": id, "PayloadDisplayName": display}
	}
	scep := payload("com.apple.security.scep", "scep", "Wi-Fi device identity")
	scep["PayloadContent"] = map[string]any{"URL": o.SCEPURL, "Name": o.Provisioner, "Challenge": challenge, "Subject": [][][]string{{{"CN", o.Identity}}, {{"OU", uuid.NewString()}}}, "KeyType": "RSA", "Keysize": 2048, "Key Usage": 5, "KeyIsExtractable": false}
	root := payload("com.apple.security.root", "root", "RADIUS server root CA")
	root["PayloadContent"] = ca
	wifi := payload("com.apple.wifi.managed", "wifi", "Wi-Fi ("+o.SSID+")")
	wifi["SSID_STR"] = o.SSID
	wifi["AutoJoin"] = true
	wifi["EncryptionType"] = "WPA"
	wifi["PayloadCertificateUUID"] = scep["PayloadUUID"]
	wifi["EAPClientConfiguration"] = map[string]any{"AcceptEAPTypes": []int{13}, "TLSAllowTrustExceptions": false, "TLSTrustedServerNames": []string{o.ServerDNS}, "PayloadCertificateAnchorUUID": []any{root["PayloadUUID"]}}
	profile := payload("Configuration", "profile", "Wi-Fi (BYOD SCEP)")
	profile["PayloadContent"] = []any{scep, root, wifi}
	return plist.Marshal(profile, plist.XMLFormat)
}
