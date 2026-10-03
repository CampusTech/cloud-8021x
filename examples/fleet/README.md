# Fleet-managed EAP-TLS profiles

Customize these reusable templates once, then deliver them through Fleet. Each
device generates its own key and receives its own certificate; no per-device
profile generator or Fleet patch is required.

| File | Platform | Purpose |
| --- | --- | --- |
| `wifi-acme.mobileconfig` | macOS / iOS | Attested ACME identity |
| `wifi-ios-byod.mobileconfig` | iOS / iPadOS User Enrollment | Dynamic Smallstep SCEP and Wi-Fi |
| `wifi-scep.xml` | Windows | Dynamic NDES-compatible SCEP machine identity |
| `wifi-8021x.xml` | Windows | Machine EAP-TLS Wi-Fi, with server name and root pins |

Both dynamic SCEP flows require `radius_vlan_policy.certificate_inventory = true`
and `enable_fleet_certificate_inventory = true`. RADIUS uses the exact certificate
fingerprint reported through authenticated Fleet results; the CSR subject cannot
select a host or VLAN. See the [deployment guide](../../docs/scep-identity-binding.md)
for staging, freshness limits, and rollback.

## Apple ACME

Use `wifi-acme.mobileconfig` for supported hardware and enrollment that provide
an attested serial. Replace `ACME_DIRECTORY_URL`, `SSID`, `RADIUS_SERVER_CN`, and
`CA_CERT_PEM` (base64 DER of the **server** trust root). Leave Fleet's serial and
certificate renewal variables intact. The subject CN must match ClientIdentifier;
the OU carries Fleet's renewal ID, which the CA template preserves. Confirm that
OU in the issued certificate and verify renewal before broad rollout.

This System-scoped example is not the serial-free User Enrollment profile.
Existing managed ACME certificates can be inventoried without reissuance; updating
older profiles lacking the renewal OU is a separate lifecycle requirement.

For macOS, keep **System mode** for device-certificate authentication before
login. **System + Login Window** is only needed for a deliberate transition to
user authentication; see [macOS authentication mode](../README.md#macos-authentication-mode).

## Apple BYOD

Register a Smallstep CA named `CANAME` in Fleet using `terraform output -raw smallstep_scep_rsa_url`,
Terraform output `fleet_scep_challenge_url`, username `fleet`, and Secret Manager's
`scep-broker-token` password. Replace `CANAME`, `SSID`, `RADIUS_SERVER_CN`, and
`RADIUS_CA_CERT_BASE64_DER` in `wifi-ios-byod.mobileconfig`.

Leave these variables intact:

- `$FLEET_VAR_SMALLSTEP_SCEP_PROXY_URL_CANAME`
- `$FLEET_VAR_SMALLSTEP_SCEP_CHALLENGE_CANAME`
- `$FLEET_VAR_CERTIFICATE_RENEWAL_ID` in the subject OU for Fleet renewal.

The profile keeps the private key nonextractable. Apple inventory uses managed
identity certificates returned by the authenticated MDM `CertificateList` command.

## Windows

Windows requires Fleet MDM **and fleetd with scripts enabled**. The collector
runs a read-only PowerShell script as SYSTEM through Fleet, reads only
`LocalMachine\My` certificates with a private key, and publishes SHA-256
fingerprints after validating the CA chain and certificate lifetime. It never
exports private keys. User-store and public-only certificates cannot qualify.

Register Fleet's **Microsoft NDES** integration with:

| Field | Value |
| --- | --- |
| URL | The RSA SCEP provisioner URL, e.g. `https://YOUR_RSA_CA_HOST/scep/wifi-scep` |
| Admin URL | Terraform output `fleet_ndes_admin_url` |
| Username | `fleet` |
| Password | Secret Manager secret `scep-broker-token` |

cloud-8021x implements the challenge endpoint itself; no Microsoft NDES server is
needed. Fleet has one NDES integration slot, also used for Okta. Check existing
NDES/Okta profiles before changing that integration. Keep credentials out of Git.

Use the [token/encoding guide](../README.md#tokens) for certificate formats,
URI escaping, and the separate client/server trust chains. `CA_CERT_PEM` in the
root profile is base64 DER, not PEM. Fleet's own Windows certificate verification
and renewal also require a current fleetd/osquery version; see
[Fleet's certificate requirements](https://fleetdm.com/guides/connect-end-user-to-wifi-with-certificate).

Deploy these three profiles:

1. `../scep/root-ca.xml`: install the RADIUS server trust root.
2. `wifi-scep.xml`: replace `CA_THUMBPRINT` with the intermediate returned by
   step-ca's SCEP GetCACert. Leave Fleet's NDES proxy/challenge, certificate ID,
   and SCEP renewal ID variables intact.
3. `wifi-8021x.xml`: replace SSID, SSID_HEX, RADIUS_SERVER_CN,
   ROOT_CA_THUMBPRINT (server trust root), and INTERMEDIATE_CA_THUMBPRINT
   (client issuer). The two CA thumbprints are distinct.

This Windows variant uses **Device** SCEP scope and **machine** Wi-Fi authentication,
including before login. The older generic `../scep/` user-auth profile is not
compatible with this collector. Migrate existing user-store certificates and
Wi-Fi profiles together, then verify a real connection and renewal before rollout.
Existing valid machine identities can be collected without reissuance.

Fleet replaces the dynamic challenge at delivery and renewal. NDES challenges
last 60 minutes to cover Fleet's 57-minute cache; Apple Smallstep challenges last
15 minutes. Neither is a network-access credential by itself.

## Variable handling

Fleet rejects repeated CA URL/challenge variable literals, including occurrences
inside XML comments. Keep exactly one live occurrence of each. Do not substitute
static shared challenges. In inventory-mode SCEP, the issuer replaces the requested CN with
`cloud-8021x-inventory` and preserves the renewal OU.
