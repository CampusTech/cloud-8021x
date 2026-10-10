# Fleet-managed SCEP with certificate inventory authorization

Use reusable Fleet profiles: native Smallstep integration for Apple BYOD and
the NDES-compatible integration for Windows machine certificates. cloud-8021x
does not need a Fleet patch or a manually minted profile for each device. Each device still generates its own private key and receives
its own certificate. Fleet delivers fresh challenges and manages renewal.

## Authorization boundary

Hardware-attested ACME can opt into a separate verified-serial path that requires
the pinned ACME signing certificate and CA-controlled provisioner marker. See
[attested ACME](dynamic-vlans.md#attested-acme-without-certificate-polling).
The fingerprint requirements below continue to apply to all SCEP certificates.

In certificate inventory mode, RADIUS authorizes the exact SHA-256 fingerprint
of the presented leaf certificate. Authenticated Fleet MDM results (Apple) or
Fleet script results (Windows) bind it to an enrolled host; the host's current
fleet selects the VLAN. The CSR Common Name, renewal OU, outer EAP username, and MAC
address cannot select a device or VLAN. There is no Common Name fallback.

On Apple, the collector requests managed identity certificates
(`ManagedOnly=true`, `IsIdentity=true`). On Windows, a read-only Fleet script runs
as SYSTEM and reads `LocalMachine\My` certificates with `HasPrivateKey=true`.
It exports only public DER, never private keys. The collector verifies the
client-auth chain and dates against the RADIUS client trust bundle, then hashes
DER. It checks the command, response host, enrollment generation, and original
result time before publishing them.
The certificate inventory API's subject/issuer/serial fields are insufficient.
Windows script results must match the requested script, execution, host, and
Fleet host enrollment timestamp (`last_enrolled_at`); current MDM enrollment is
required separately. This timestamp tracks osquery enrollment; an Orbit-only
script-agent credential reset does not change it. Apple uses its MDM enrollment generation. Freshness uses
script request creation time conservatively;
rereading a result never extends its lifetime. This trusts the enrolled Fleet agent
running as SYSTEM, not hardware attestation. User-store and public-only
certificates are excluded. Windows inventories over 9,000 output characters fail
closed before Fleet can truncate the response; inspect the script result when
coverage is missing on a host with many machine certificates.

Unknown, ambiguous, unenrolled, or stale certificates fail closed. RADIUS still
verifies the certificate chain and proof of private-key possession. A device
claiming another device's UUID in its CSR cannot inherit that device's VLAN.
This relies on authenticated MDM/Fleet agent enrollment, not hardware attestation.

The dynamic challenge broker accepts Fleet's HTTP Basic credentials over HTTPS
and returns a random, signed challenge scoped to the SCEP provisioner. Apple
Smallstep challenges last 15 minutes. Windows NDES challenges use a separate
token version valid for 60 minutes, covering Fleet's 57-minute NDES cache.
Challenges allow retries until expiration; they are **not single-use**. They
permit issuance but do not assert a device identity or authorize network access.
The SCEP template issues clientAuth certificates without requested SANs and
forces the reserved CN `cloud-8021x-inventory`, ignoring the requested CN.
Legacy CN authorization explicitly rejects that reserved identity. Keep
this CA dedicated to this Wi-Fi use: other services must not authorize these
certificates using their untrusted subjects.

The public challenge routes are `/fleet/scep-challenge` (Apple) and
`/fleet/ndes-challenge` (Windows). step-ca's authorization
endpoint remains on loopback with mutual TLS. The load balancer also uses HTTPS
to the broker, and the VM firewall allows that port only from Google's load
balancer ranges. The broker credential (`scep-broker-token`) is separate from the
server-only `scep-challenge-signing-key`; never give the signing key to Fleet or
devices. Both RADIUS nodes share the signing key, so challenges survive backend
switches.

## Configuration and staging

Use the [parallel deployment guide](deployment/parallel-green.md),
[protected bootstrap](bootstrap/README.md) and
[validated YAML example](../examples/cloud-8021x.yaml). The unified application
release includes the broker and CA authorization handlers; there is no separately
installed webhook release or executable alias. Merging a PR does not activate
workers, change enrollment backends or deliver Fleet profiles.

Configure the Fleet observer and scoped certificate collector as separate
credentials in Secret Manager. The collector needs host/result reads, managed
Apple `CertificateList` commands and Windows script execution/result reads.
Windows requires fleetd with scripts enabled. An observer account alone cannot
issue commands; scope maintainer access to the required fleets.

Stage the RADIUS server root and DNS name in client profiles before cutover.
Existing CA identities and server trust must match the signed adoption source;
this deployment supports the preserved Smallstep CA and does not add an Okta
trust mode. CA HTTPS hostnames need their existing working enrollment frontdoors.
AP RADIUS addresses can be IPs. See
[trust roots](../examples/README.md#choose-the-correct-trust-root).

Fingerprint enforcement requires fresh bindings for every SCEP client in scope.
Attested ACME has a separate verified-serial path and can avoid certificate
polling when the configured ACME profile is verified and no relevant SCEP
profile is installed. The collector supports Apple macOS, iOS and iPadOS, and
Windows machine certificates; Windows user-store certificates are excluded.
Never resolve missing bindings with an untrusted subject fallback.

Certificate commands/scripts use configured cadence and a durable PostgreSQL
pending budget shared by both nodes. Results are polled during inventory sync.
Freshness uses original MDM response time or Windows request creation time, not
when the result is reread. Offline devices can remain pending. A Windows POST
with a lost response remains quarantined even if no execution ID is known.
Investigate retained reservations rather than deleting them to resend.

The broker requires the self-hosted CA and certificate inventory authorization.
Collection alone does not authorize neutral SCEP issuance. Preparation remains
passive until the protected activation and frontdoor cutover succeed.

## Register the CA and deliver one profile

In Fleet's certificate enrollment integrations, add a **Smallstep** CA named
`CANAME` with:

| Field | Value |
| --- | --- |
| SCEP URL | `https://YOUR_RSA_CA_HOST/scep/wifi-scep` (use your provisioner name) |
| Challenge URL | Terraform output `fleet_scep_challenge_url` |
| Username | `fleet` |
| Password | Secret Manager secret `scep-broker-token` |

Use the native Smallstep integration, not the static custom SCEP integration.
Fleet tests the authenticated challenge endpoint when saving the configuration.
The broker has a dedicated Cloud Armor per-IP throttle, configured with
`scep_broker_requests_per_minute` (default `1000`). Size it for enrollment and
renewal bursts from Fleet's shared outbound IP. Excess requests receive HTTP
429 and may need Fleet delivery retries; the broker does not impose a timed
IP ban. The separate CA backend rate limit remains unchanged.
Keep the credential out of Git and command output.

Customize [the reusable profile](../examples/fleet/wifi-ios-byod.mobileconfig)
once: replace `CANAME`, `SSID`, `RADIUS_SERVER_CN`, and
`RADIUS_CA_CERT_BASE64_DER`. The last value is the base64 DER of the **RADIUS
server trust root**, which may differ from the client-issuing CA. Distribute
through Fleet's normal managed configuration profile workflow.

Leave the Fleet variables intact. Fleet replaces the dynamic SCEP proxy URL and
challenge for each delivery. The requested host UUID is not an authorization input and is replaced by the
reserved CN at issuance; the renewal ID in the OU lets Fleet track renewal. Private keys are nonextractable,
and Wi-Fi server trust is restricted to the configured name and root.

## Windows enrollment and migration

Configure Fleet's Microsoft NDES integration with the same RSA SCEP URL and
Basic credentials above, using Terraform output `fleet_ndes_admin_url` as its
Admin URL. No NDES server or Fleet patch is required: cloud-8021x serves the
compatible challenge response. Check existing Fleet profiles and integrations
before replacing the single NDES configuration.

Deliver [the Windows SCEP profile](../examples/fleet/wifi-scep.xml),
[the machine Wi-Fi profile](../examples/fleet/wifi-8021x.xml), and the
[server root trust profile](../examples/scep/root-ca.xml). See the
[template instructions](../examples/fleet/README.md#windows) for substitutions.
Fleet keeps the renewal ID in the subject OU and supplies a fresh challenge.

The Windows collector requires **machine certificates** and scripts running as
SYSTEM. Migrate any existing User-scoped SCEP and user-auth Wi-Fi profiles to
Device scope and machine authentication together. Collect existing machine
certificates before enforcement where possible. A real Windows pilot must check
certificate installation, Fleet script completion, both VMs' coverage, initial
EAP-TLS, correct site-specific VLAN and DHCP, pre-login authentication, and renewal. Local
protocol tests do not substitute for that Windows pilot.

## Friday-to-Tuesday rollout checks

1. Enable collection and check coverage on both RADIUS VMs. Existing managed
   certificates can be used if they already chain to the configured client trust
   bundle; a mass reissue is not inherently required for fingerprint binding.
2. Enable fingerprint enforcement, register the broker in Fleet, and pilot the
   reusable profiles on a real User Enrollment iPhone, managed Mac, and Windows
   machine (including machine-certificate migration). Verify
   installation, initial EAP-TLS, VLAN, DHCP, and profile replacement/renewal.
3. Deliver the profile through Fleet. Devices need internet through home Wi-Fi,
   cellular, or an onboarding network until their new certificate is observed.
   A queued command or elapsed weekend is not proof that a device is ready.
4. During Monday connectivity, refresh and inspect each VM's current authorization snapshot and readiness:

   ```sh
   sudo /usr/local/bin/cloud-8021x inventory sync --config /etc/cloud-8021x/config.yaml
   sudo /usr/local/bin/cloud-8021x doctor --config /etc/cloud-8021x/config.yaml
   ```

   Resolve missing, unsupported, ambiguous, stale, or unenrolled hosts. Inspect Fleet command results and the published snapshot for exact certificate
   bindings and original timestamps. A
   certificate can be observed without a Wi-Fi profile selecting it, so confirm
   Fleet's profile installation status as well. Validate an actual connection
   before treating any cohort as complete.
5. Keep an onboarding network available Tuesday for devices that remained offline
   or whose certificate observations expired. The default 24-hour observation
   lifetime requires recent contact; extending it increases the removal-detection
   window for a certificate on a still-enrolled host. Current enrollment/group
   data has a separate, shorter expiry.

If rolling back broker/profile delivery, preserve fingerprint enforcement while
neutral SCEP certificates remain trusted. The bootstrap records a persistent
`/var/lib/cloud-8021x/fingerprint-enforced` marker and refuses to remove enforcement
on subsequent runs. Withdraw the issuing CA or retire those certificates before
manually removing the marker. The reserved CN also blocks those certificates in
legacy VLAN policy, but disabling the VLAN policy entirely removes that check. Changing a challenge key does not revoke certificates.
The `webhook_allow_label` setting continues to scope attested ACME and legacy
identity-bound issuance; neutral SCEP issuance cannot evaluate a host label.
Use VLAN group rules to scope network access.

Existing active Wi-Fi sessions are not disconnected automatically; VLAN changes
apply on authentication. This feature does not send CoA.

## Other integrations and upstream Fleet work

The normalized certificate cache remains MDM-independent. Another trusted MDM
adapter can publish exact certificate fingerprints and device groups without
embedding Fleet concepts in RADIUS.

The unified `cloud-8021x scep-challenge` and `cloud-8021x profile` commands support
integrations that deliberately mint identity-bound profiles. They
are not required for this Fleet-managed workflow. With fingerprint enforcement
disabled, the webhook continues to reject neutral challenges and requires the
older identity-bound token plus current enrollment.

[Fleet PR #54717](https://github.com/fleetdm/fleet/pull/54717) proposed device
context in dynamic challenge requests. It was closed because authenticated
certificate inventory removes that dependency.

References: [Fleet built-in variables](https://fleetdm.com/guides/fleet-variables),
[Fleet certificate inventory](https://fleetdm.com/guides/view-certificates-in-host-vitals),
[Fleet MDM command APIs](https://fleetdm.com/docs/rest-api/rest-api#commands),
[Apple CertificateList](https://developer.apple.com/documentation/devicemanagement/certificatelistcommand).
