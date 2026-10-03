"""Exercise private per-device profile delivery through the real issuer CLI."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/byod_profile.py"


@unittest.skipUnless(shutil.which("go") and shutil.which("openssl"), "requires Go and OpenSSL")
class BYODGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.shared.cleanup)
        cls.binary = Path(cls.shared.name) / "webhook"
        result = subprocess.run(
            ["go", "build", "-o", str(cls.binary), "."], cwd=ROOT / "webhook",
            capture_output=True, text=True,
        )
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.cert = Path(cls.shared.name) / "ca.pem"
        result = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(Path(cls.shared.name) / "ca.key"), "-out", str(cls.cert),
            "-subj", "/CN=Test RADIUS CA", "-days", "1",
        ], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stderr)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.key = self.directory / "signing.key"
        self.secret = "private-server-signing-key-keep-this-off-the-device"
        self.key.write_text(self.secret + "\n")
        self.key.chmod(0o600)
        self.profile = self.directory / "device.mobileconfig"
        self.command = self.directory / "fleet-command.json"
        self.identity = "a491d2b3-e27b-4d7a-a3b7-798fd5ad6574"

    def run_cli(self, *extra, success=True):
        result = subprocess.run([
            sys.executable, str(SCRIPT), "--webhook-bin", str(self.binary),
            "--identity", self.identity, "--provisioner", "wifi-scep",
            "--scep-url", "https://ca.example.com/scep/wifi-scep",
            "--ssid", "Campus & <Guests>", "--radius-server-name", "radius.example.com",
            "--radius-ca-cert", str(self.cert), "--signing-key-file", str(self.key),
            "--out", str(self.profile), *extra,
        ], capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn(self.secret, result.stdout + result.stderr)
        return result

    def test_real_issuer_profile_and_single_device_fleet_delivery(self):
        result = self.run_cli("--fleet-command-out", str(self.command), "--debug")
        raw = self.profile.read_bytes()
        profile = plistlib.loads(raw)
        payloads = {p["PayloadType"]: p for p in profile["PayloadContent"]}
        scep = payloads["com.apple.security.scep"]
        root = payloads["com.apple.security.root"]
        wifi = payloads["com.apple.wifi.managed"]
        config = scep["PayloadContent"]
        self.assertEqual(config["Subject"][0], [["CN", self.identity]])
        self.assertEqual(config["URL"], "https://ca.example.com/scep/wifi-scep")
        self.assertEqual(config["Name"], "wifi-scep")
        token = config["Challenge"]
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        self.assertEqual(claims["identity"], self.identity)
        self.assertEqual(claims["provisioner"], "wifi-scep")
        self.assertEqual(claims["exp"] - claims["iat"], 900)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertNotIn(self.secret.encode(), raw)
        self.assertFalse(config["KeyIsExtractable"])
        self.assertEqual(wifi["SSID_STR"], "Campus & <Guests>")
        self.assertEqual(wifi["PayloadCertificateUUID"], scep["PayloadUUID"])
        eap = wifi["EAPClientConfiguration"]
        self.assertEqual(eap["PayloadCertificateAnchorUUID"], [root["PayloadUUID"]])
        self.assertEqual(eap["TLSTrustedServerNames"], ["radius.example.com"])
        self.assertFalse(eap["TLSAllowTrustExceptions"])
        self.assertEqual(root["PayloadContent"], ssl.PEM_cert_to_DER_cert(self.cert.read_text()))
        request = json.loads(self.command.read_text())
        self.assertEqual(request["host_uuids"], [self.identity])
        command = plistlib.loads(base64.b64decode(request["command"]))
        self.assertEqual(command["Command"]["RequestType"], "InstallProfile")
        self.assertEqual(command["Command"]["Payload"], raw)
        for path in (self.profile, self.command):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_profile_identifiers_stable_on_renewal_and_distinct_across_hosts(self):
        self.run_cli()
        first = plistlib.loads(self.profile.read_bytes())
        self.profile.unlink()
        self.run_cli()
        second = plistlib.loads(self.profile.read_bytes())
        self.assertEqual(first["PayloadIdentifier"], second["PayloadIdentifier"])
        self.assertEqual(first["PayloadUUID"], second["PayloadUUID"])
        self.assertNotEqual(first["PayloadContent"][0]["PayloadContent"]["Subject"][1],
                            second["PayloadContent"][0]["PayloadContent"]["Subject"][1])
        self.profile.unlink()
        self.run_cli("--identity", "other-enrollment-id")
        third = plistlib.loads(self.profile.read_bytes())
        self.assertNotEqual(first["PayloadIdentifier"], third["PayloadIdentifier"])

    def test_dry_run_validates_without_minting_or_files(self):
        fake = self.directory / "issuer"
        fake.write_text("#!/bin/sh\necho SHOULD_NOT_RUN >&2\nexit 1\n")
        fake.chmod(0o700)
        self.run_cli("--webhook-bin", str(fake), "--dry-run", "--fleet-command-out", str(self.command))
        self.assertFalse(self.profile.exists())
        self.assertFalse(self.command.exists())

    def test_existing_or_invalid_output_cannot_leave_partial_profile(self):
        self.command.write_text("keep me")
        self.run_cli("--fleet-command-out", str(self.command), success=False)
        self.assertEqual(self.command.read_text(), "keep me")
        self.assertFalse(self.profile.exists())
        self.profile.write_text("keep profile")
        self.run_cli(success=False)
        self.assertEqual(self.profile.read_text(), "keep profile")
        self.profile.unlink()
        self.run_cli("--fleet-command-out", str(self.directory / "missing/command.json"), success=False)
        self.assertFalse(self.profile.exists())

    def test_rejects_invalid_issuance_inputs_without_output(self):
        invalid = [
            ("--scep-url", "http://ca.example.com/scep/wifi-scep"),
            ("--scep-url", "https://fleet.example.com/api/v1/fleet/scep/proxy"),
            ("--scep-url", "https://ca.example.com/scep/wrong-provisioner"),
            ("--scep-url", "https://secret@ca.example.com/scep/wifi-scep"),
            ("--ttl", "25h"), ("--ttl", "0s"),
            ("--identity", " "), ("--radius-ca-cert", str(self.key)),
            ("--fleet-command-out", str(self.profile)),
        ]
        for args in invalid:
            with self.subTest(args=args):
                self.run_cli(*args, success=False)
                self.assertFalse(self.profile.exists())

    def test_der_certificate_and_nondefault_ttl(self):
        der = self.directory / "ca.der"
        der.write_bytes(ssl.PEM_cert_to_DER_cert(self.cert.read_text()))
        self.run_cli("--radius-ca-cert", str(der), "--ttl", "1h30m")
        profile = plistlib.loads(self.profile.read_bytes())
        token = profile["PayloadContent"][0]["PayloadContent"]["Challenge"]
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        self.assertEqual(claims["exp"] - claims["iat"], 5400)

    def test_issuer_failure_is_private_and_leaves_no_profile(self):
        fake = self.directory / "issuer"
        fake.write_text("#!/bin/sh\ncat '" + str(self.key) + "' >&2\nexit 1\n")
        fake.chmod(0o700)
        self.run_cli("--webhook-bin", str(fake), success=False)
        self.assertFalse(self.profile.exists())

    def test_second_output_failure_removes_first_private_output(self):
        spec = importlib.util.spec_from_file_location("byod_profile", SCRIPT)
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        original_open = os.open

        def fail_second(path, flags, mode):
            if path == self.command:
                raise OSError("disk unavailable")
            return original_open(path, flags, mode)

        with patch.object(generator.os, "open", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "disk unavailable"):
                generator.write_outputs([(self.profile, b"private profile"), (self.command, b"private command")])
        self.assertFalse(self.profile.exists())
        self.assertFalse(self.command.exists())


if __name__ == "__main__":
    unittest.main()
