# Dynamic VLAN assignment

`radius_vlan_policy` maps inventory groups to VLANs for EAP-TLS connections.
The RADIUS policy is MDM-independent: it reads a local normalized inventory
snapshot and identifies the device from the validated certificate Common Name.
Existing serial CNs (including the Windows ` Campus WiFi` suffix) and opaque
MDM enrollment identifiers are supported. Outer EAP `User-Name` and client MAC
addresses never select a VLAN.

## Configuration

```hcl
enable_fleet_lookup = true
fleet_api_base_url  = "https://fleet.example.com"

radius_vlan_policy = {
  group_vlans = {
    "fleet:1" = 100
    "fleet:2" = 200
  }
  cache_max_age = 3600
  # fallback_vlan = 999
}
```

Use Fleet **fleet/team IDs**, not host IDs or names. `fleet:0` is Unassigned.
The Fleet adapter accepts both `fleet_id` and the older `team_id` API field.
The existing Jamf computer inventory adapter maps sites as `jamf:site:<id>`;
it does not fetch Jamf mobile-device inventory or smart-group membership.
Enable one existing inventory integration or supply a custom snapshot as below.

VLAN IDs must be integers from 1 to 4094. The built-in cache requires a lifetime
of at least 600 seconds; custom cache paths allow 60 seconds or more. A null policy (the default) disables
VLAN authorization and preserves the existing EAP-TLS behavior. An enabled
policy rejects:

- Unknown, ambiguously identified, or unenrolled devices.
- Missing, malformed, future-dated, or expired inventory snapshots.
- Devices with no mapped group, unless `fallback_vlan` is configured.
- Devices whose mapped groups select different VLANs.

A fallback applies only to known enrolled devices with no matching rule. It
never admits an unknown device or bypasses a failed inventory lookup.

Built-in inventory refreshes run at boot and every **five minutes** while VLAN
policy is enabled (30 minutes otherwise). Only a complete successful inventory
fetch replaces the policy snapshot; API failures retain the previous snapshot
until `cache_max_age` expires. Background enrichment lookups do not refresh
policy or prolong authorization. A newly enrolled device may wait until the
next complete refresh. To refresh immediately on each RADIUS VM:

```sh
sudo /usr/local/bin/fleet-device-cache.sh
# Or, for Jamf: sudo /usr/local/bin/jamf-device-cache.sh
```

Membership changes take effect on the next authentication after refresh. This
also applies to TLS resumption: FreeRADIUS restores the certificate attributes,
then the policy evaluates the current inventory. Missing restored identity
fails closed. This feature does not disconnect existing sessions or send CoA.
The existing FreeRADIUS 3/OpenSSL session-cache limitations still apply.

## UniFi setup

The Access-Accept contains these standard, untagged RADIUS attributes:

```text
Tunnel-Type = 13
Tunnel-Medium-Type = 6
Tunnel-Private-Group-Id = "200"
```

FreeRADIUS debug output may display `VLAN` and `IEEE-802`; the actual packet
encodes the numeric values **13** and **6**. The VLAN ID is a string.

1. Create the target VLAN networks, routing, DHCP, and firewall rules in UniFi.
2. Allow those VLANs on the AP/switch uplinks.
3. Configure the cloud-8021x servers and shared secret in the UniFi RADIUS profile.
4. Enable **RADIUS Assigned VLAN Support** for the applicable network type.
5. Select that RADIUS profile on the WPA2/WPA3 Enterprise SSID.

You do not need UniFi Local Credentials entries for certificate-authenticated
clients. UniFi's local-user examples describe its built-in server; cloud-8021x
supplies the same attributes from the external server. Accepted auth logs include
`vlan_id` and `cert_cn` for verification.

References: [UniFi RADIUS setup](https://help.ui.com/hc/en-us/articles/360015268353-Configuring-a-RADIUS-Server-in-UniFi),
[RFC 3580 section 3.31](https://www.rfc-editor.org/rfc/rfc3580#section-3.31).

## BYOD iOS/iPadOS without serial numbers

Apple User Enrollment omits hardware serial and UDID from attestation. The
existing ACME authorization path still requires an attested identifier; do not
replace it with a self-asserted CSR identity. Use SCEP for these BYOD devices.

- Generic MDM template: [`wifi-ios-byod.mobileconfig`](../examples/scep/wifi-ios-byod.mobileconfig).
- Fleet template: [`wifi-ios-byod.mobileconfig`](../examples/fleet/wifi-ios-byod.mobileconfig).

The Fleet template uses `$FLEET_VAR_HOST_UUID`, which resolves to the enrollment
ID for user-enrolled iOS/iPadOS devices. RADIUS treats that value as an opaque
identifier; it contains no Fleet-specific certificate naming convention. The
Fleet inventory adapter associates it with the host's fleet. Re-enrollment can
change this identifier and requires a newly issued certificate/profile.

For Fleet, register the existing RSA step-ca SCEP provisioner as a custom SCEP
proxy named `CANAME`, then replace `CANAME` in the template with that registration
name. The URL and challenge tokens must each occur only once. The OU renewal
identifier is separate from the device identity; it is not a policy group.

Replace `SSID`, `RADIUS_SERVER_CN`, and `RADIUS_CA_CERT_BASE64_DER` with the SSID,
expected RADIUS server certificate name, and base64 DER of the **RADIUS server's
trusted root CA**. This root need not be the SCEP client-issuing CA. Generic MDM
users also replace `DEVICE_IDENTIFIER`, `CERTIFICATE_RENEWAL_ID`, `SCEP_PROXY_URL`,
`SCEP_CA_NAME`, and `SCEP_CHALLENGE` using their MDM's enrollment workflow.

The profiles do not require supervision or disable private Wi-Fi addresses.
The RADIUS trust bundle must trust the SCEP issuer. The self-hosted SCEP webhook
requires release **1.2.0** for UUID/enrollment-ID lookup; merge/release that binary
before applying the new default `webhook_release_version`. No release or
infrastructure deployment occurs merely by pushing this branch.

### Issuance trust boundary

VLAN isolation depends on the CA binding the certificate identity to the actual
enrolled device. An enrollment ID is an identifier, **not proof of ownership**.
The existing step-ca SCEP gate checks the shared upstream challenge and whether
the requested CN exactly matches an enrolled serial or UUID. Fleet's proxy
checks its host/profile URL challenge but forwards the encrypted CSR; this does
not bind the CSR CN to that host.

Consequently, a requester who can reuse the shared upstream SCEP challenge can
request a certificate naming another enrolled device and obtain that device's
VLAN. This limitation predates dynamic VLANs, but matters for segmentation.
Use an issuer/registration authority that enforces per-device identity binding
(e.g. per-device challenges bound to the requested CN) before relying on SCEP
certificates as a hostile-BYOD isolation boundary. Keeping the shared challenge
secret from outsiders alone does not establish that binding. The VLAN policy
cannot repair an incorrectly authorized certificate.

References: [Fleet variables](https://fleetdm.com/guides/fleet-variables),
[Apple Managed Device Attestation](https://support.apple.com/en-us/guide/deployment/dep28afbde6a/web),
[Fleet SCEP proxy](https://github.com/fleetdm/fleet/blob/main/ee/server/service/scep/scep_proxy.go).

## Other MDMs / inventory sources

Set `radius_vlan_policy.cache_file` to an absolute path containing this format:

```json
{
  "version": 1,
  "updated_at": 1790985600,
  "identities": {
    "opaque-enrollment-identifier": {
      "device_id": "your-inventory-record-id",
      "groups": ["employees"],
      "enrolled": true
    }
  }
}
```

Map `employees` in `group_vlans`. `updated_at` is the Unix time of the complete
inventory snapshot, not a certificate timestamp. Use one entry per supported
certificate identity, normalizing UUIDs to lowercase hyphenated form. Different
aliases can point to the same record. Ambiguous aliases must be omitted or null.
Keep the file root-owned and readable by `freerad`; publish atomically with
`rename`, only after a complete successful refresh. Provide the file on both
RADIUS nodes. The built-in adapters write only their default cache path and do
not overwrite a custom snapshot.

## Validation

```sh
python3 -m unittest discover -s tests -v
terraform validate
cd webhook && go test ./... && golangci-lint run
```

The Docker integration test documented in `tests/README.md` exercises actual
FreeRADIUS 3.x EAP-TLS exchanges and decodes the RADIUS VLAN attributes. A final
on-network check with the target UniFi AP and an enrolled iOS device is still
needed to verify profile delivery, switch trunks, DHCP, and client placement.
