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

Use the [per-device profile generator](scep-identity-binding.md#generate-and-deliver-an-ios-profile)
for the self-hosted CA. Supply the device's Fleet host UUID/enrollment ID from
trusted inventory. The generator binds the challenge and CSR CN to that value
and can produce a Fleet InstallProfile request targeting exactly that host.
RADIUS treats the value as an opaque identifier; the inventory adapter maps it
to the host's fleet. Re-enrollment may change it and requires a new profile.

The generator supports unsupervised iOS/iPadOS, keeps private Wi-Fi addresses,
and configures explicit trust for the **RADIUS server root and name**. That root
need not be the SCEP client-issuing CA. The RADIUS trust bundle must trust the
client issuer. The [generic mobileconfig](../examples/scep/wifi-ios-byod.mobileconfig)
is also available for trusted MDM integrations that supply their own per-device
bound challenge.

The self-hosted flow requires webhook **2.0.0**, which must be released before
applying the Terraform version pin. Fleet's static custom-SCEP profile templates
are not compatible with this protected issuer. Native dynamic SCEP support is
planned once Fleet can send device identity in its challenge request; for now,
use the per-device generator and deliver a fresh profile for renewal.

### Issuance trust boundary

The shared-password impersonation path is closed by signed, expiring challenges
bound to the requested CN and provisioner. The issuer checks current enrollment,
and the CA requires the authorization webhook over authenticated mutual TLS.
An enrollment ID alone is still not proof of device ownership: the trusted MDM
integration must deliver each token only to its assigned device. Keep the signing
key server-side. The [migration guide](scep-identity-binding.md) covers existing
certificates, which are not revoked by an issuance-code change.

References: [Fleet variables](https://fleetdm.com/guides/fleet-variables),
[Apple Managed Device Attestation](https://support.apple.com/en-us/guide/deployment/dep28afbde6a/web).

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
