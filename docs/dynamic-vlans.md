# Dynamic VLAN assignment

`radius_vlan_policy` maps inventory groups to VLANs for EAP-TLS connections.
The RADIUS policy is MDM-independent: it reads a local normalized inventory
snapshot. Recommended Apple BYOD mode identifies devices by the SHA-256
fingerprint of their verified certificate, as observed through authenticated MDM.
Legacy deployments can still use a securely issued certificate Common Name. Outer EAP `User-Name` and client MAC
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

### Different VLAN IDs at each location

Use `locations` when the same fleet needs different VLAN IDs in different
offices. Location names must exactly match the office keys in `radius_clients`.
For example, the Secure fleet (`fleet:1`) can use VLAN 100 in NYC and VLAN 110
in ATL:

```hcl
radius_clients = {
  nyc = { cidrs = ["198.51.100.10/32"] }
  atl = { cidrs = ["203.0.113.20/32"] }
}

radius_vlan_policy = {
  certificate_inventory = true
  locations = {
    nyc = {
      group_vlans = { "fleet:1" = 100, "fleet:2" = 200 }
    }
    atl = {
      group_vlans = { "fleet:1" = 110, "fleet:2" = 220 }
    }
  }
}
```

The addresses above are documentation examples; use each site's actual RADIUS
egress IP/CIDR. Each office already has its own shared secret. FreeRADIUS uses
the matched, authenticated client's configured `shortname` as the location.
`NAS-Identifier`, `NAS-IP-Address`, SSID, and device-supplied names cannot override
it. Offices behind the same RADIUS proxy/egress need distinct trusted client
paths before they can use separate location policies.

Each location supplies a complete mapping and may specify its own
`fallback_vlan` for known enrolled devices without a mapped group. When
`locations` is nonempty, top-level `group_vlans`/`fallback_vlan` are not inherited;
unknown locations and missing mappings are rejected. With `locations` omitted
or empty, the original global mapping continues to work.

No certificate or profile changes are needed when a device moves between offices.
The current office's mapping is evaluated on authentication, including legacy
TLS resumption. The certificate readiness report includes each host's VLAN and
readiness per configured location; overall readiness requires all locations to
have a valid assignment.

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

Membership changes take effect on the next authentication after refresh. Legacy CN mode also rechecks policy on TLS resumption using restored certificate
attributes. Fingerprint mode disables resumption and obtains the actual leaf
certificate on every authentication. Missing certificate bindings fail closed. This feature does not disconnect existing sessions or send CoA.
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

Use the [reusable Fleet profile](../examples/fleet/wifi-ios-byod.mobileconfig)
and [deployment guide](scep-identity-binding.md). Fleet's native Smallstep
integration obtains a fresh dynamic challenge for delivery and renewal. No Fleet
patch or individually generated profiles are required.

Enable `enable_fleet_certificate_inventory` to collect managed Apple identity
certificates, and `radius_vlan_policy.certificate_inventory` to authorize only
exact fingerprints. The collector maps authenticated MDM results to the enrolled
host; the current fleet selects its VLAN. CSR CNs and renewal OUs cannot authorize
a device. Unknown, ambiguous, and stale fingerprints fail closed.

This mode applies to all clients on these RADIUS servers. The built-in collector
supports macOS, iOS, and iPadOS only; assess existing Windows or other MDM clients
before enabling enforcement. The coverage report on each VM distinguishes trusted
certificate observations from valid VLAN mappings. Initial enrollment and renewal
require connectivity until MDM reports the new certificate. See the guide for
staging, freshness limits, and Friday-to-Tuesday rollout checks.

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

For fingerprint mode use version 2 and a `certificates` map instead of subject
identities. Set `certificate_inventory = true`; `certificate_max_age` limits
how long a certificate observation remains usable, separately from `cache_max_age`:

```json
{
  "version": 2,
  "updated_at": 1790985600,
  "identities": {},
  "certificates": {
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": {
      "device_id": "your-inventory-record-id",
      "groups": ["employees"],
      "enrolled": true,
      "observed_at": 1790985500
    }
  }
}
```

Keys are lowercase SHA-256 of exact leaf DER, not certificate serials or SHA-1.
`observed_at` must be the original authenticated device report time; rereading a
cached API result must never renew it. Publish ambiguous fingerprints as null or
omit them. Bind observations to the current MDM enrollment generation.

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
