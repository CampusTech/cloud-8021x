# Task11 synthetic guest acceptance controller

Development-only source. This binary is not a release artifact. It has not been
run inside the four-node guest. The accepted ordering and independent gates are
in `../systemd-fixture/full-acceptance-design.md`.

## Current execution boundary

`--dry-run` prints a closed stage plan without inspecting the host. On non-Linux
systems every executing command refuses. Linux execution requires the existing
root-owned `/etc/cloud8021x-task11-fixture` marker (`synthetic-only-v1`), root for
controller/transfer/seed operations, and reviewed private enrollment. These
checks identify the fixture; they do not replace the separate launch approval.
No code here creates that outer marker, starts machines, installs packages,
creates product receipt keys, signs product receipts, or fabricates activation,
fence, peer-readiness, database, or successful acceptance markers.

`cutover` invokes the independently pinned real cloud primitive verifier and
then **refuses** at the separately missing installed passive/reboot/mount/API
auditor. Its separately owned implementation is not integrated here yet. No handwritten
success JSON can release it. The R123 activation sequence behind that gate keeps
business intake unavailable, permits both green API callers only after first
actual activation returns waiting-for-peer, then requires the remaining actual
CLI results plus SQL/PID1 checks before enabling intake. API permission is not
product activation; failures retain an explicit reconciliation obligation.

The other stages invoke real shipping commands, but their zero exit status means
only those commands exited zero. It does not prove passive start denial, reboot
persistence, EAP/accounting, actual KMS, SQL/OTLP reconciliation, mount/cgroup
behavior, or rollback refusal under pending work. Those independent gates still
require the approved installed fixture.

## Concrete platform input

Read-only controller location: `/usr/local/libexec/task11-acceptance`. Private
control directory: `/var/lib/cloud8021x-task11/control`, root-owned mode0700.
The root-reviewed `enrollment.json` is mode0600 and has these case-sensitive
field names (digest/ID values below are descriptions, not executable inputs):

```json
{
  "Schema": 1,
  "ApplicationSHA256": "exact final shipping app SHA256",
  "ControllerSHA256": "exact compiled development controller SHA256",
  "Cloud": {
    "HelperSHA256": "separately reviewed installed cloud executable SHA256",
    "PrimitiveSeedSHA256": "exact primitive-api/seed.json bytes SHA256",
    "PrimitiveExpectedSHA256": "independently reviewed primitive expected.json SHA256",
    "InstalledSeedSHA256": "exact original-seed/api/seed.json bytes SHA256",
    "OriginalStateSHA256": "exact retained original certificate-state.json SHA256"
  },
  "Passive": {
    "ObserverSHA256": "reviewed installed observer executable SHA256",
    "ObserverSourceSHA256": "reviewed observer source receipt SHA256",
    "CloudSourceSHA256": "reviewed cloud source receipt SHA256",
    "ApplicationSourceSHA": "clean shipping app 40-character Git revision",
    "OriginalSeedSHA256": "exact original-seed/original-manifest.json SHA256",
    "Manifests": {}
  },
  "Nodes": {
    "blue-primary": {"MachineID":"32 lowercase hex", "Hostname":"task11-blue-primary", "Pin":"", "ConfigSHA256":"staged raw YAML SHA256"},
    "blue-secondary": {"MachineID":"different 32 lowercase hex", "Hostname":"task11-blue-secondary", "Pin":"", "ConfigSHA256":"staged raw YAML SHA256"},
    "green-primary": {"MachineID":"different 32 lowercase hex", "Hostname":"task11-green-primary", "Pin":"", "ConfigSHA256":"staged raw YAML SHA256"},
    "green-secondary": {"MachineID":"different 32 lowercase hex", "Hostname":"task11-green-secondary", "Pin":"", "ConfigSHA256":"staged raw YAML SHA256"}
  }
}
```

Fixed machine names are `task11-<node>`; fixed roots are
`/var/lib/cloud8021x-task11/roots/task11-<node>`. These must already exist and be
registered nspawn containers with genuine systemd PID1. The builder currently
has only a canary; this controller does not assume four-node enrollment exists.
Each operation obtains fresh Leader/start/root/boot/namespace evidence. Stable
machine IDs and enrolled roots survive reboot; Leader and namespace IDs are not
pinned across reboots. All five namespaces must differ from the outer guest and
from the other nodes. Open namespace/root descriptors prevent PID reuse from
retargeting nsenter between verification and execution.

All four nodes must already contain exact app/62 archives/manifest/config/PG CA
under `/var/cache/cloud-8021x/artifacts`. Config and manifest are root0600. The
shipping CLI independently verifies every artifact. Primary source and primary
green use identical role configuration; likewise secondary. The common pair
manifest must match; physical instance/deployment/epoch/release pins remain
those validated by production code. Fixed deployment IDs are `task11-blue` and
`task11-green`.

Executing stages must run under the single reviewed outer
`task11-acceptance.service` candidate in this directory. Root writes private
`control/stage.json` as `{"stage":"keys"}` (or another closed stage), then starts
that fixed service. No template instances or concurrent stage services exist.
The `stage` entry point parses only that fixed input. Direct stage CLI calls
outside the fixed delegated service refuse before entering a machine. Dry-run
remains host-independent.

The controller verifies its actual PID1 MainPID/ControlGroup, Delegate=yes,
KillMode=control-group and SendSIGKILL. Each namespace operation is born through
UseCgroupFD in a new exclusive root-owned cgroup-v2 child, with its directory
inode/device pinned. Timeout or helper exit kills only that subtree and requires
an independently read `cgroup.events` populated0 before release. Unknown
quiescence quarantines the controller and keeps its stage lock. PID1 cleanup of
the single service handles unexpected controller death; already-started business
services are prior side effects requiring product reconciliation. The actual
cross-PID-namespace/descendant-death/unrelated-process proof is still a REQUIRED
unexecuted guest gate, so I2 is not closed by unit tests or compilation.

One explicit requested stage at a time:

1. `task11-acceptance keys`: real staged `bootstrap source-key --incoming` on
   all four; require four distinct public pins; update only those config fields
   and the artifact manifest's config digest. Never read/copy private receipt
   keys. Per-node enrollment checkpoints retain partial progress. A crash
   between atomic config/manifest writes fails closed and needs review.
2. `task11-acceptance prepare`: require actual source FreeRADIUS/EC/RSA units
   active; actual capture, corresponding private transfer, actual green prepare,
   repeated for the second role. Independent passive/reboot audits follow.
3. `task11-acceptance cutover`: require actual pinned primitive cloud verifier,
   independent prepared observer/reboot/API window, then refresh both source
   captures/prepares and recheck both passive nodes before the first activation.
   Actual activate primary must wait for its peer. Grant both green API
   permissions immediately before secondary/primary activation; business intake
   remains unavailable until actual SQL and PID1 workers-active proof passes.
4. `task11-acceptance deactivate`: installed deactivate on both greens, revoke
   both green API permissions, freeze independently validated inventory phase
   manifests, and run actual deactivated observer/reboot/API window.
5. `task11-acceptance proofs`: installed rollback-proof on both greens, then
   transfer both signed proofs to both original nodes. Pending/uncertain work
   must be reconciled with actual supported commands first; this tool does not
   force reconciliation or reinterpret a refusal as success.
6. `task11-acceptance resume`: staged resume-source on both originals; actual
   shipping verification decides whether schedulers may resume.

Transfers allow only the product's two parallel and two rollback receipt slots.
Source, controller and destination independently verify pinned signature,
role/config/release/deployment/epoch/freshness. Private bytes travel only local
child pipes. Destination uses no-follow directory/file opens, owner/mode/link
checks, atomic0600 rename, fsync and digest acknowledgement. Evidence contains
only public operation/status, byte count and digest; maximum4096 records per
control directory. Each subprocess has a deadline and output bound; namespace operations additionally
require delegated subtree cleanup and terminal population evidence. Stderr is
never echoed. Child output is discarded on failure. A failed step requires
inspection of genuine product state before retry, not a fake completion record.

## Synthetic original seed and source service

`task11-acceptance seed` reads root0600 `control/seed-spec.json` with fields
`Project` (`task11-*`), `ECDNS`, `RSADNS`, `ServerDNS`, `ECDB`, `RSADB`, and
`ObservedAt` (original UTC whole-second RFC3339 timestamp). For the installed
cloud scenario, `Remote` supplies `ApplicationSHA256`, `FleetAuthorization`,
`IntakeHost` and `IntakeAPIKey` (private synthetic credentials; never real tokens).
The intake host must match an actual supported `otlp.<Datadog site>` authority.
DSNs must point at
owned `10.203.11.11`, use `postgresql`, fixed stepca user/databases and TLS
verify-full. The output directory `control/original-seed` is exclusive: reruns
cannot renew or replace original identity. Generation does not install it.

Outputs include:

- `source/`: genuine EC P256 and RSA4096-root/RSA2048-intermediate CA chains,
  proper independent SCEP decrypters, production-rendered CA configs/templates,
  self-signed loopback webhook, server leaf/key/chain, shared Class key,
  original V2 fingerprint cache, original sticky fingerprint guard and pending
  certificate state. No accounting ledger/checkpoint/history is generated.
- `api/`: PKCS8 intermediate KMS keys, existing cloud helper schema1 seed with
  numeric resources and immutable version1 secret bytes. Private KMS keys never
  appear in source authority trees. TLS/metadata, remaining credentials and
  stateful scenarios are the cloud fixture owner's inputs, not fake successes.
- `nas/`: genuine allowlisted client leaf/key; `private-original/`: synthetic
  original root keys, never installed in a CA authority or printed.

Original host UUID is `11111111-2222-4333-8444-555555555555`, Fleet hostID1,
opaque device/group IDs `fleet:1`; the only NAS is `10.203.11.40/32`, location
`task11`, numeric UniFi VLAN120. Original command
`task11-retained-command-0001` is an Apple CertificateList pending command with
its exact original enrollment and timestamp. The seed also contains a minimal
`source/etc/cloud8021x-task11-source-provenance.json`: exact approved original
snapshot plus retained certificate-state/enrollment digests, without private
command bodies. Install this file root-owned0444. Root source-render and capture
preflight independently verify the original private state against it; the policy
service reads only this protected projection. A 404 remains unresolved. No
arbitrary Username or serial is accepted as identity.

`source-render` reads the independently prepared root-owned
`/etc/cloud8021x-task11-source.yaml` (strict valid product YAML with deployment
empty, physical blue hostname, fingerprint mode, original cache/Class paths,
loopback policy address127.0.0.1:9082, and the exact synthetic NAS/rule above).
It reads actual protected credential references and renders the shipping native
configuration into private `control/source-native`, plus a policy service and
synthetic source-refresh service/timer candidate. It does not install/start them.
The fixture builder must apply those candidates with the native/runtime ownership
expected by shipping helpers, supply real source SQL/TLS/config credentials and
start actual CA/native services under the separately approved launch.

`source-policy` runs only as the existing cloud8021x user on the matching blue
host. It reuses the real local policy HTTP/fingerprint handoff/Class boundaries;
it does not construct app RuntimeServices or issue a handoff itself. The actual
shipping verified-leaf helper and strict native TLS configuration must supply
that handoff. The fixed synthetic cache is bound to that original projection on initial read
and every refresh. Replacing a fingerprint, changing identity/groups/enrollment,
or advancing any observation or inventory freshness is rejected. Only backdating
inventory updated_at (without changing certificate/identity observations) is an
explicit stale-negative input. Invalid updates empty the authorization snapshot
and terminate the source fixture with an error; they are not hidden behind an
old still-authorizing cache. The source writer command holds the actual legacy source lock and writes
only a labeled private heartbeat, never a renewed certificate or authorization.

This source fixture is not evidence of the retired Python implementation. It
uses shipping native/CA and a narrowly configured development policy endpoint
so genuine capture/fencing/reversal can be tested without restoring rlm_python.
CA database population and ongoing original services, private credential
ownership, read-only lower-layer exposure, capacity, installed source helper
sudoers/config and complete post-activation traffic remain execution gates.

## Local verification

Only pure/helper tests and compilation are authorized at this preparation stage:

```text
go test -race ./tests/runtime/task11-acceptance -count=1
GOOS=linux GOARCH=arm64 go build ./tests/runtime/task11-acceptance
GOOS=linux GOARCH=arm64 golangci-lint run ./tests/runtime/task11-acceptance/...
```

The tests use temporary synthetic keys and files, never live systemd, root
product paths, machines, external APIs or databases. Test-only signed envelopes
exercise the verifier; executable controller source never signs an envelope.

## Review correction status

I1: generated staged argv now omits `--config`; the actual shipping root parser
selects its protected incoming file only through `--incoming`. Tests call the
actual app.NewCommand root guard, not just inspect argv text. No product guard
changed.

I3: tests bind genuine seed policy to retained certificate provenance, reject
identity-record mismatches, replacement leaves and freshness advancement, and
preserve the explicit stale-inventory negative.

I2: the optional Linux `TASK11_NESTED_RED=1` test is an intentional negative
reproducer of the original group-only primitive. It must not be interpreted as
an accepted controller execution mode. Default tests skip it. The delegated
cgroup wrapper fixes the source-level mechanism, and unit tests fail closed on
missing, malformed, duplicated, unreadable or still-populated evidence. Actual
UseCgroupFD/cgroup.kill behavior across the real nspawn PID namespace is pending
and must pass before the finding can close or full launch can proceed.

## SQL, command recovery and remote evidence integration

New closed stages are `observe`, `recover` and `verify-cloud`. Their names do not
claim successful execution. The source is compiled and tested in-process only;
actual SQL/schema/role/namespace/installed helper verification remains unexecuted.

`observe` requires a real unactivated, unrevoked SQL epoch and zero business outbox rows, then
creates an exclusive root0600 `display-before.json`. Cutover also freezes it after final prepare and before the first activate; an existing baseline must match exactly. It binds each node's actual
configuration and exact rendered display semantics before traffic. The two
reviewed API hosts supply no optional serial/name/model/owner data. Production
NewDisplay must emit identical neutral fields for actual, fresh and stale cache
states; changing only updated_at is therefore safe. Other devices, meaningful
display metadata or network providers refuse. Raw inventory hashes remain
diagnostics. Production telemetry.Project builds expectations independently of
intake; config or rendered semantic differences refuse rather than reconstruct
changed historical enrichment.

Node SQL extraction holds the actual protected writer-operation lock and uses
one connection from the existing migration capacity reserve, with the exact
protected migration DSN, existing production TLS validation, private host
10.203.11.11 and isolated cloud8021x_task11_green database/role. It runs a bounded
REPEATABLE READ READ ONLY transaction. Root-only recovery tables justify the
migration credential; no runtime/CA roles or privileges are changed. Fixed reads
bind actual epoch, transition, manifest, work ID/generation/payload, attempt outcome
and original receipt. Uncertain/pending/unmatched outbox work refuses verification.
Original PostgreSQL payload bytes travel as opaque base64 byte slices, so private
JSON transport cannot compact/re-escape them before the recovery digest is built.
Sender and receiver independently enforce strict payload JSON, 1152 work/128 guard
rows and a24MiB raw total. The complete encoded observation has a separate32MiB
limit including base64 expansion, projected records and metadata; oversized
responses refuse before emitting partial private output. A near-limit raw snapshot
may therefore be rejected even though its unencoded payload fits24MiB. The
shipping recovery command still checks its independently fetched original PG hash.
No SQL Admin API call is needed for extraction; the real shipping bootstrap may
still require its separately seeded instance-CA static route.

`recover` requires an actually revoked SQL epoch. It derives original guard/work
identities from SQL and independently pinned retained certificate state, advances
only the bounded remote pending/missing/terminal scenarios, and invokes actual
shipping state recover-collection or state recover-work --kind fleet-terminal.
No POST/republication action is available. Pending and missing must refuse; the
terminal step must commit genuine matching SQL proof. Unknown execution IDs or
unrecorded original attempt time bounds remain refusals. Retained original seed
currently contains one Apple command; no legacy Windows script/nonce is invented.
Green exact request serialization for Apple and Windows is tested against the
actual shipping Fleet collector with an in-process transport. The separately
pinned API seed adds exactly Windows hostID2 /
22222222-3333-4444-8555-666666666666 with scripts enabled and enrollment one day
before seed observation. Original source policy/cache/provenance remain Apple
host1 only. Cutover arms accepted-uncertain collection before green API permission.
The actual shipping collector supplies the new UUID/SYSTEM script/nonce and SQL
attempt; the fixture never seeds successful work.

A fixed root0600 atomic remote-state.json read supplies only the learned Windows
execution ID as an untrusted locator, bound to the exact SQL command/host and
immutable seed hash. No remote request/script/body becomes expected evidence.
The real shipping GET-only recovery independently verifies its exact original
script, nonce, enrollment and timestamp before committing proof. This models a
remote API outcome, not execution on a real Windows device.

After deactivation and recovery, `verify-cloud` projects both actual SQL snapshots,
requires matching records/outbox identities, writes fixed root0600 expected.json,
computes its independent SHA before calling the pinned verifier, and requires its
strict complete result. The expected file never comes from intake. Original-state,
seed and helper pins must be reviewed actual bytes. A development cloud helper
build receipt is available separately; it is not installed enrollment or a seed
pin. Fixed /proc/self/fd execution retains
the checked verifier inode through launch. Every control subprocess remains in
the owned operation cgroup, whose actual cross-PIDnamespace acceptance is pending.


## Independent installed passive observation (R135 source preparation)

The pending refusal is replaced with executable, fail-closed integration. None
of the installed operations below has been launched by this source-preparation
slice. The reviewed helper contracts and compiled controller do not constitute
reboot, SQL, namespace, cloud traffic, or installed acceptance evidence.

`seed` emits a root0600 original-manifest.json over a closed set of20 actual
original input files, including private spec.json and API seed. Review its exact
bytes independently before setting Passive.OriginalSeedSHA256. Source secrets
remain private guest files. Each observation revalidates these original files,
original certificate-state and API seed pins. ObserverSourceSHA256 and
CloudSourceSHA256 bind the reviewed source receipts in enrollment; executable
SHA pins enforce the corresponding installed bytes. Assembly must independently
review that mapping; no receipt hash is an execution-success assertion.

Before each actual prepare, the controller verifies the actual signed source
capture against its public pin and expected deployment/config/release/epoch.
It derives the expected24 slots through shipping CA validation, rendering and
server adoption. In particular, installed client trust contains intermediates
and roots; installed native/cache chains include the intermediate. Raw original
roots/cache bytes cannot replace these transformations. The actual completed
KnownInstallation and ParallelInstalledReceipt are required before the root0600
fixed `/etc/cloud8021x-task11-passive-seed.json` can be installed. Its digest is
retained separately under enrollment.Passive.Manifests for each node and phase.

The fixed observer runs only as `/usr/local/libexec/task11-passive-audit observe`
through a retained, hashed root-owned executable FD inside the existing pinned
namespace/cgroup operation. Each request binds the clean shipping source,
application/config/helper/seed hashes and freshly inspected boot/namespaces.
The strict response must match that request, independent preserved slots, actual
prepared SQL identities/fences, completed generation state and passive units.
Only public metadata/digests enter evidence; private source material is cleared.

The controller retains each actual API baseline before preparation or the
reboot window, then calls final with its exact peer, seed, cursor and prefix
hash. Zero reads is valid; any mutation attempt or policy change refuses. These
API windows are separate from product observations. Deactivation starts a new
window only after both genuine product deactivations and explicit API permission
revocations; previously active traffic is not relabeled passive. Proof/resume
stages recheck the deactivated pair and retain their own API windows.

Reboot calls fixed machinectl for only the enrolled node. A pidfd must prove
old Leader termination; refreshed registration must preserve enrolled root,
machine ID and hostname with a changed BootID. The observer then runs again in
fresh namespaces. Content/ownership/modes, SQL/work/guard/fences and persistent
collector UUID/backing inode/size/capacity must match. Volatile file inode/device
and namespace IDs are not mistaken for stable reboot identity. Timeout or
uncertainty refuses onward progress and retains actual prior side effects.
Actual nspawn restart behavior, operation cgroup cleanup across PID namespaces,
unchanged unrelated sentinels and the complete reboot comparison remain required
guest gates; no unit fixture substitutes for those observations.

Deactivated inventory is the only mutable preserved slot. After actual completed
installation/receipt validation, the real atomic published snapshot is decoded
and compared with the original certificate provenance and exact independently
seeded two-host projection. The original Apple fingerprint/group/enrollment/
observed timestamp authority must remain identical. Only the approved Windows
identity may be added, with no new certificates or serial authority, exact group
and enrollment. Neutral display equivalence permits updated_at variation;
changed display or authority refuses. Only then is the actual publication hash
frozen before reboot. All other23 slots, original manifest and certificate-state
pins stay unchanged. No SQL inventory-generation table or intake-derived
historical expectation is invented.
