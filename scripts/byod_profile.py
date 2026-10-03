#!/usr/bin/env python3
"""Create a private iOS Wi-Fi profile for one trusted inventory identity.

The administrator selects the identity; never expose this command as a device
self-service issuer. The server signing key stays local. Output is deliberately
not uploaded: a Fleet command targets exactly the identity that was certified.
Renewal requires a freshly generated and delivered profile before cert expiry.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import plistlib
import re
import ssl
import subprocess
import sys
import tempfile
from urllib.parse import quote, urlsplit
import uuid


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--webhook-bin", required=True, type=Path,
                        help="Trusted cloud-8021x webhook binary with scep-challenge support")
    parser.add_argument("--identity", required=True,
                        help="Exact device identity selected from trusted MDM inventory; Fleet host UUID for Fleet delivery")
    parser.add_argument("--provisioner", required=True, help="Exact step-ca SCEP provisioner name")
    parser.add_argument("--scep-url", required=True, help="Direct HTTPS step-ca /scep/<provisioner> endpoint")
    parser.add_argument("--ssid", required=True)
    parser.add_argument("--radius-server-name", required=True)
    parser.add_argument("--radius-ca-cert", required=True, type=Path, help="RADIUS CA certificate, PEM or DER")
    parser.add_argument("--signing-key-file", required=True, type=Path, help="Server-only signing key file")
    parser.add_argument("--ttl", default="15m", help="Challenge validity in whole seconds, minutes or hours; max 24h")
    parser.add_argument("--out", required=True, type=Path, help="New private .mobileconfig file; never overwritten")
    parser.add_argument("--fleet-command-out", type=Path,
                        help="Optional new private JSON body for Fleet POST /api/v1/fleet/commands/run")
    parser.add_argument("--dry-run", action="store_true", help="Validate inputs without issuing a challenge or writing files")
    parser.add_argument("--debug", action="store_true", help="Log non-secret operation metadata")
    return parser.parse_args()


def read_ca(path):
    source = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in source:
        if source.count(b"-----BEGIN CERTIFICATE-----") != 1:
            raise ValueError("--radius-ca-cert must contain exactly one CA certificate")
        pem = source.decode("ascii")
        der = ssl.PEM_cert_to_DER_cert(pem)
    else:
        der = source
        pem = ssl.DER_cert_to_PEM_cert(der)
    # Parse X.509, not merely its base64 encoding. No network or trust bypass.
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=pem)
    return der


def validate(args):
    for name, limit in (("identity", 1024), ("provisioner", 256)):
        value = getattr(args, name)
        if not value or value != value.strip() or len(value.encode()) > limit:
            raise ValueError(f"--{name} must be a nonempty exact inventory value")
    if args.identity.endswith(" Campus WiFi"):
        raise ValueError("--identity must be the inventory identity without the legacy certificate suffix")
    if not args.ssid or len(args.ssid.encode()) > 32:
        raise ValueError("--ssid must contain between 1 and 32 UTF-8 bytes")
    if not args.radius_server_name or args.radius_server_name != args.radius_server_name.strip():
        raise ValueError("--radius-server-name is required")
    url = urlsplit(args.scep_url)
    if (url.scheme != "https" or not url.hostname or url.username is not None
            or url.password is not None or url.query or url.fragment
            or url.path.rstrip("/") != "/scep/" + quote(args.provisioner, safe="")):
        raise ValueError("--scep-url must be the direct HTTPS /scep/<provisioner> endpoint without credentials or query")
    # Match the issuer's whole-second lifetime constraint without minting during dry-run.
    if not re.fullmatch(r"(?:[0-9]+[smh])+", args.ttl):
        raise ValueError("--ttl must use whole seconds, minutes or hours (for example 15m or 1h30m)")
    seconds = sum(int(n) * {"s": 1, "m": 60, "h": 3600}[unit]
                  for n, unit in re.findall(r"([0-9]+)([smh])", args.ttl))
    if not 1 <= seconds <= 86400:
        raise ValueError("--ttl must be between 1 second and 24 hours")
    if not args.webhook_bin.is_file() or not os.access(args.webhook_bin, os.X_OK):
        raise ValueError("--webhook-bin must be an executable file")
    if len(args.signing_key_file.read_bytes().strip()) < 32:
        raise ValueError("--signing-key-file must contain at least 32 bytes")
    outputs = [args.out] + ([args.fleet_command_out] if args.fleet_command_out else [])
    if len({p.resolve() for p in outputs}) != len(outputs):
        raise ValueError("Output paths must be distinct")
    for path in outputs:
        if path.exists() or path.is_symlink():
            raise ValueError(f"Output already exists: {path}")
        if not path.parent.is_dir():
            raise ValueError(f"Output directory does not exist: {path.parent}")
    return read_ca(args.radius_ca_cert)


def profile_bytes(args, ca, challenge):
    # Stable identity per device/network lets InstallProfile replace the old
    # profile at renewal. Different devices can never replace each other's profile.
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(
        ["cloud-8021x/byod", args.identity, args.provisioner, args.ssid]))

    def payload(kind, role, display):
        identifier = str(uuid.uuid5(namespace, role)).upper()
        return {"PayloadType": kind, "PayloadVersion": 1,
                "PayloadIdentifier": "org.cloud8021x.byod." + identifier,
                "PayloadUUID": identifier, "PayloadDisplayName": display}

    scep = payload("com.apple.security.scep", "scep", "Wi-Fi device identity")
    scep["PayloadContent"] = {
        "URL": args.scep_url, "Name": args.provisioner, "Challenge": challenge,
        "Subject": [[["CN", args.identity]], [["OU", str(uuid.uuid4())]]],
        "KeyType": "RSA", "Keysize": 2048, "Key Usage": 5, "KeyIsExtractable": False,
    }
    root = payload("com.apple.security.root", "root", "RADIUS server root CA")
    root["PayloadContent"] = ca
    wifi = payload("com.apple.wifi.managed", "wifi", "Wi-Fi (" + args.ssid + ")")
    wifi.update({
        "SSID_STR": args.ssid, "AutoJoin": True, "EncryptionType": "WPA",
        "PayloadCertificateUUID": scep["PayloadUUID"],
        "EAPClientConfiguration": {
            "AcceptEAPTypes": [13], "TLSAllowTrustExceptions": False,
            "TLSTrustedServerNames": [args.radius_server_name],
            "PayloadCertificateAnchorUUID": [root["PayloadUUID"]],
        },
    })
    profile = payload("Configuration", "profile", "Wi-Fi (BYOD SCEP)")
    profile["PayloadContent"] = [scep, root, wifi]
    return plistlib.dumps(profile, sort_keys=False)


def issue(args):
    with tempfile.TemporaryDirectory(prefix="cloud8021x-challenge-") as directory:
        token_path = Path(directory) / "challenge"
        result = subprocess.run([
            str(args.webhook_bin.resolve()), "scep-challenge", "--identity", args.identity,
            "--provisioner", args.provisioner, "--signing-key-file", str(args.signing_key_file.resolve()),
            "--ttl", args.ttl, "--out", str(token_path),
        ], capture_output=True, check=False)
        # Never echo issuer stdout/stderr: third-party wrappers may print secrets.
        if result.returncode:
            raise ValueError("Challenge issuer failed; check the trusted binary, signing key and binding inputs")
        token = token_path.read_text().strip()
        if not token or len(token) > 4096:
            raise ValueError("Challenge issuer returned an invalid token length")
        return token


def write_outputs(outputs):
    created = []
    try:
        for path, data in outputs:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main():
    args = arguments()
    try:
        ca = validate(args)
        # Validate plist field encoding even during dry-run, before issuing anything.
        profile_bytes(args, ca, "dry-run")
        if args.dry_run:
            print("Valid per-device profile inputs; no challenge issued or files written.")
            return 0
        profile = profile_bytes(args, ca, issue(args))
        outputs = [(args.out, profile)]
        if args.fleet_command_out:
            command = plistlib.dumps({
                "CommandUUID": str(uuid.uuid4()),
                "Command": {"RequestType": "InstallProfile", "Payload": profile},
            }, sort_keys=False)
            body = {"host_uuids": [args.identity], "command": base64.b64encode(command).decode("ascii")}
            outputs.append((args.fleet_command_out, (json.dumps(body) + "\n").encode()))
        write_outputs(outputs)
        print("Private per-device profile written. Deliver before the challenge expires; renewal requires fresh output.")
        if args.debug:
            print(f"Wrote {len(outputs)} private file(s); no API calls made.", file=sys.stderr)
        return 0
    except (OSError, ValueError, UnicodeError, ssl.SSLError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
