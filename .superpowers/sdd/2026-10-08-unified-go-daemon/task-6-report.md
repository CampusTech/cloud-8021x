# Task 6 implementation and native evidence

Implemented on `codex/unified-go-daemon`, reviewed starting HEAD
`87c6f2477546884a3bd3c1cced17c9dc39afa9d1`. Only Task 6 and the controller-approved
source-contract extensions are included. No push, merge, release, production
installation, actual host service, tenant API, cloud/firewall or Fleet mutation.
FreeRADIUS, step-ca and Datadog remain backends. Python exists only in development
packet orchestration; no server Python hook, Go accounting parser/spool or
accounting REST path was added.

## Final implementation

- Embedded real native radiusd, clients, EAP-TLS, certificate policy REST,
  final-auth detail, accounting detail, buffered detail reader and PostgreSQL
  configuration. Native policy failure/overload is checked in the certificate
  virtual server before EAP success/MPPE. Fingerprint TLS resumption is disabled;
  legacy resumption re-evaluates current policy. Static IPv6 CIDRs generate both
  IPv6 auth/accounting listeners in addition to IPv4.
- Native REST uses the module's typed JSON encoder, not an interpolated JSON
  string. `decodeNative` preserves occurrence arrays, rejects ambiguous trusted
  server context, and accepts numeric uint32 NAS-Port-Type. Reply values have
  `do_xlat=false`. Only exactly one numeric value 19 retains configured WiFi;
  configured Wired can never upgrade. Other/missing/duplicate values retain
  verified authentication and signed Class with no VLAN. Logs preserve native
  NAS-Port-Type values and occurrence count rather than declaring physical wired
  transport from a conservative policy downgrade.
- Narrow `ClientResolver.AuthenticatedClient` supports original static TrustMap
  callers and the applied-state SourceTrust resolver. Shared `sources.FromConfig`
  replaces duplicated app construction. Static IPv6 is part of the same protected
  configuration identity; dynamic candidates/firewall stay public IPv4 /32.
- Accounting captures actual source/client/location, original server receipt,
  host, native random replay identity, packet ID/authenticator and original NAS
  delay before buffering. Only native buffered replay calls SQL. Catchall plain
  INSERT preserves nullable scalar text and occurrence counts; no numeric casts
  discard counters before the shared Go ledger validates them. Native driver
  `auto_escape=yes` preserves quotes/backslashes/Unicode correctly. Zero rows,
  SQL failure and connection/TLS failure do not advance replay. Startup SQL
  connections are zero; pool max 2, retry 5 seconds, bounded connection/query time.
- Final-auth detail is separate and suppresses passwords, EAP/MSK/EMSK/session
  material, MPPE keys, bearer/handoff and TLS certificate/session descriptors
  before disk. Auth write failure remains observational. Go `auth.Reader`
  imports bounded escaped final records only, retains incomplete tails/files,
  pins descriptor-relative paths/UID/GID/mode/link counts, and commits cursor,
  immutable event and outbox via Task 3's atomic `AuthEvent` API. Identity is
  verified signed Class at original receipt; display enrichment reads local
  inventory/network snapshots only. Missing display values are `N/A`.

## Superseding source-freshness contract

**The temporary embedded `c8021x_expires` implementation is superseded and absent
from final rendering.** Static client bytes remain stable when only discovery
observation time changes. Dynamic client entries contain protected source kind,
configuration SHA, SHA-256 of configured client ID and bounded integer MaxAge.
The coherent native patch adds the zero-argument `source_fresh` rlm_expr xlat.

The fixed root is `/var/lib/cloud-8021x-source-proof`. `current` is a root-owned
regular 0644 file containing exactly one 64-character lowercase hex generation,
without newline. It is not a symlink or arbitrary path. Lookup is
`<generation>/<config SHA>/<client SHA>/<actual transport IPv4>`. Directories are
root-owned, not group/world writable; published generation/config/client dirs
are 0555. Markers are zero-byte, root-owned, single-link 0444 regular files.
Every component is opened descriptor-relative with O_NOFOLLOW. Unsafe pointer,
component, marker, malformed property, nonempty xlat argument, future mtime or
expired observation fails closed. Native receipt time is the packet's actual
server timestamp, never Event-Timestamp/Acct-Delay-Time. Static clients explicitly
bypass discovery expiry. No general file-stat xlat or per-packet Go/process/API.

Root stages and fsyncs the complete proof generation, installs clients only if
their bytes differ, validates configuration, activates only changed clients,
checks health/firewall convergence, rechecks original candidate freshness,
writes public source state, then atomically replaces the protected pointer last.
Rollback restores original bytes/state/pointer and avoids restart when restored
client bytes are unchanged. Freshness-only healthy updates still validate and
converge but never call Radius.Activate. Reconciliation is read-only and verifies
the exact original generation, tree contents and marker mtimes along with exact
clients/state/firewall/health. Native replay does not reauthorize old accepted
records using replay time; records accepted while fresh remain replayable later.

Publication ordering matters: public state can become visible just before the
native pointer. A scheduled `SourceTrust.Refresh` reads validated state outside
the hot path and retains original observations/config binding. In that short
interval the old native proof still gates incoming auth/accounting, so a new
public state cannot bypass stale native trust. After pointer publication, a Go
reader still holding older state may conservatively reject until its next refresh.
A failed refresh clears dynamic cached state while static trust stays available.
Write/rename/fsync ambiguity is not a claim of multi-resource atomicity; Task 9
must use the existing uncertain-attempt/read-only reconciliation workflow.

Generation derivation is SHA-256 of JSON-marshaled `Plan` (declared field order,
configured client order, canonical sorted CIDRs, floored original observation
seconds, protected integer MaxAge/config SHA and configured binding fields).
`ExpectedProofGeneration(cfg, originalCandidates, now)` validates/derives this
reference without authenticating/publishing or refreshing expired timestamps.
`ReconciliationEvidence.ProofGeneration` returns the verified applied reference;
`Backup.Proof/ProofExist` carries the previous pointer. Task 8/9 should record the
returned reference in receipts and retain current, previous and unresolved work
references. Deriving old unresolved references requires the original protected
configuration as well as candidate JSON; if unavailable, retain conservatively.
The staging directory is bounded to 4096 entries including abandoned stages.
Controller explicitly assigns coordinated cleanup to Task 8/9; without cleanup,
five-minute refreshes reach that bound in roughly 14 days and fail closed.

## Authenticated source, coherent package and loaded artifact

Final version: **`3.2.10+dfsg-2~bookworm+campus3`**, full arm64 Debian source build
against Bookworm ABI. 3.2.1 is only the stock failure baseline, never the final
artifact. No sid/trixie binary packages, copied standalone modules, module magic
bypass or mixed family. The source/build fixture is
`cloud8021x-daemon-fr-c7d492`, Debian 12 image ID
`sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251`.

Exact source files and SHA-256 are committed in `patches/freeradius/source.sha256`:

- `.dsc`: `44970f7e84c6a675814e93990bf2cb333e2dc93914542cb0d5e716fbc307649a`
- orig tar: `e2b840b46763ec9891731f54ec502b9fd459ad209c228aaaba9b09f236a5ce86`
- Debian tar: `4ec6e9c9e1ff04a7d0c45da981cb1d97c4ec3abe2a67f3e5738aab66985b90e0`

`apt-get source --download-only freeradius=3.2.10+dfsg-2` used authenticated signed
source metadata. `dscverify --no-conf` reported Good signature and both archives
validated. Independent `gpgv --status-fd 1 --keyring
/usr/share/keyrings/debian-keyring.gpg` reported VALIDSIG
`D6E01EC516A5DFCEF71956D3775079E5B850BC93` (Bernhard Schmidt), signature
2026-09-10 11:24:56 UTC. The sid InRelease signature was independently verified
with the Debian archive keyring: subkey
`B8E5F13176D2A7A75220028078DBA3BC47EF2265`, primary
`04B54C3CDCA79751B16BC6B5225629DF75B188BD`; metadata SHA
`0c6d3bb2607dcf106976353b656c3b3abd99f22fc1a538c5094c53c136bbd917`.
These are authenticated provenance checks, not merely first-observed hashes.

Full `dpkg-buildpackage -us -uc -j4` succeeded from a fresh verified extraction.
The explicit committed Bookworm packaging rebase removes unavailable
dh-sequence-installsysusers, uses existing debhelper `--with=installsysusers`,
permits Bookworm libwbclient-dev and changes unsupported sysusers `u!` to `u`.
The final exact diff does not modify LDAP dependencies. Native packet tests do
not enable unused AD/EAP modules. Campus2's initial package configure failure
on `u!` was repaired by campus3; no success claim relies on partially configured
packages. Campus3 all seven packages report fully installed matching versions.
`passwd -S freerad` reports locked (`L`). Runtime libs are libc 2.36-9+deb12u14,
OpenSSL 3.0.22-1~deb12u1, libpq 15.19-0+deb12u1, libcurl 7.88.1-10+deb12u15;
systemd sysusers is Bookworm 252.39. No foreign binary ABI was introduced.

Committed `campus3-arm64-artifacts.sha256`, `.buildinfo`, installed TSV and
`campus3-arm64-loaded.txt` record artifacts, dependencies and actual loaded proof.
The selected source C and packaging files were compared byte-for-byte against a
second fresh extraction using the committed recipe/patches; simulated build-dep
resolution succeeded. The recipe describes the executed build contract; moving
APT repositories are not falsely presented as a byte-reproducible release build.
Task 10 must pin dated dependencies/image and sign retained distribution artifacts.

Actual process PID 192599 reached Ready to process requests. A disposable,
networkless observer in its PID namespace with only SYS_PTRACE beyond dropped
capabilities captured mappings; observer was removed. Matched mapped device/inode,
installed stat, dpkg ownership and independent extraction from the final .deb:

| Artifact | SHA-256 | Actual mapped/stat identity |
|---|---|---|
| freeradius | `9e3669dcc3684aa3633eca432698efd005395c551a62e6dbf3e793abab9ba6d7` | device 00:41 / 0x41, inode 16037739 |
| rlm_detail.so | `ab6fe8f1e697a424e5c7f69aae62ffd2c209a3bc8a8b489d91034597b46021ab` | device 00:41 / 0x41, inode 16037689 |
| rlm_expr.so | `e737b9eb9ab6cdf66bbcbc2061b2b97bf6d863330988c39eb443163b71ff4712` | device 00:41 / 0x41, inode 16037706 |

No mapping was deleted. EAP-TLS, REST, SQL PostgreSQL and all three native
libfreeradius libraries mapped from the matching package directory as well.
The full build/log/artifact collection remains `/task6-secure-build` in the
reserved fixture; full maps are `/private/tmp/task6-loaded-campus3-maps.txt`.

## RED/GREEN and native protocol evidence

Meaningful REDs included missing NASPortTypes/native-decoder APIs, static IPv6
rejected by actual policy SourceTrust construction, missing stable proof publisher
API, lack of configured IPv6 listeners, and reader/native metadata mismatch.
Each has a passing focused regression. New source-refresh tests prove unchanged
activation count, failed validation preserving old pointer/no restart, and
reconcile rejecting a modified original mtime. The entire sources test binary
also ran inside Linux as actual root with protected `/run/task6-go-tests` ancestry.

The stock fixture `/tmp/native-flush-probe.log` was inspected: on 3.2.1,
`native_flush_probe` writing `/dev/full` returned `ok` and sent Accounting-Response
(lines 579-586). Final matched campus3 `full` gate returned no accounting ACK;
normal EAP still accepted when the separate observational auth detail used
`/dev/full`. The patch checks ferror/fclose and releases the native handle once.

Actual final campus3 modes executed via the Python development harness (with
`freeradius -XC` and actual Go-generated configuration before each native start):

- `test`: valid fingerprint EAP-TLS accepted with Tunnel-Type=13,
  Tunnel-Medium-Type=6, VLAN 200 and signed Class. Wrong chain, expired/unknown
  leaf, ambiguous fingerprint, expired inventory, unenrolled identity rejected.
  Wired NAS 15, duplicate 19+15, absent and unknown 999 authenticated normally
  without VLAN. Current-policy full reauthentication accepted then rejected after
  enrollment changed and never reported resumed=1.
- Real bounded Go HTTP overload (authenticated incomplete bodies occupying the
  handler slots) and stopped policy service rejected before EAP success or MPPE.
  Accounting still ACKed with policy unavailable. No vendor/network lookup was
  involved in authorization.
- `legacy`: actual resumed TLS (`resumed=1`) accepted then rejected after the
  inventory enrollment changed. `attested`: actual EC issuer, permanentIdentifier
  and ACME provisioner type 6 accepted; wrong provisioner type 8 rejected. These
  modes and the main suite checked newly appended auth bytes for suppressed
  EAP/MPPE/bearer/handoff/TLS fields. Legacy cache exposed two public TLS metadata
  attributes in an earlier log generation; final templates suppress them, and
  the reader tolerates/ignores those two descriptors in retained earlier records.
- `sources`: fresh accounting ACK, natural expiry suppressed ACK, root protected
  pointer refresh resumed ACK **with identical PID and /proc start time**.
  Future/wrong config/wrong source/missing marker, writable or wrong-owner marker,
  nonempty/hardlinked/symlink marker, writable directory and malformed/oversized/
  symlink/missing pointer all suppressed ACK. Fresh EAP accepted, expired EAP
  rejected, static fallback accepted. Failed root apply never freshened a pointer
  in the Go transaction tests. Accounting replay bypasses this receipt-time guard.
- `zero`: successful SQL affecting zero rows retained pending detail. `outage`:
  stopped **own disposable** PostgreSQL, EAP still accepted, accounting ACKed and
  native detail remained after retries. App auth ingestion returned shared DB
  unavailable with no cursor advancement or file deletion. After PG restart,
  native replay drained. Replaying the same retained campus3 detail produced two
  rows with replay ID
  `fae28bc622ec6623ea0c31fa6a22c5b86c5bda99040064f0c7e1ef4d1e8e9a39`
  and identical original received_at, then shared ledger classified duplicates.
- `sqltls`: native PostgreSQL wrong hostname and wrong CA each rejected the TLS
  connection and retained detail after NAS ACK. Restored verified TLS replayed it.
- Actual Start/Interim/Stop, duplicate fields, unknown 77 status, missing status,
  missing counters and duplicate counters reached raw intake. Native SQL preserved
  session `quote'\\雪`, session_count=2, class_count=2; 4294967295 low/high words;
  packet ID and 34-character hex-prefixed authenticator. Shared ledger observations
  contain exact upload/download `18446744073709551615`; quarantine contains
  invalid_status, invalid_counter and invalid_session_identity. Native packet
  dictionary decoding still defines what malformed wire attributes reach detail;
  there is no claim that invalid wire integer encodings become valid scalar text.
- NAS-IPv6-Address preserved `2001:db8::9`. `ipv6` additionally exercised actual
  IPv6 transport: source `::1`, NAS `2001:db8::9`, trusted office/nyc attribution.
  Static IPv6 policy construction, canonical/mapped/zoned/zero-prefix/overlap
  validation and strict IPv4 dynamic discovery have Go regressions.
- `permissions`: actual app UID1000 has only its primary group, events and separate
  spool-metadata group; no freerad/shadow/ssl-cert. Freerad UID100 has only freerad
  and events. App cannot read native DSN, RADIUS secret, backend key, SQL/REST
  configuration or accounting bytes; can read final auth, cannot write it, can
  stat spool metadata. Freerad cannot traverse the app's private handoff directory.
  Actual fixed sudo helper rejected a traversal leaf path. Valid EAP continued
  using the real helper under these groups.
- Final actual auth ingestion after outage/retention imported pending records,
  and the immediate next poll imported 0. Unit tests cover escapes, Unicode/
  malformed grammar, incomplete tail completion, DB failure before commit,
  generation rotation/restart identity, truncation, symlink/hardlink/public file,
  oversize bounds and local metadata ambiguity. No accounting bytes are parsed
  by these tests or the product Go reader.

Validation commands: `go test -race ./...` passed; after the final focused
reader/IPv6 changes, `go test -race ./internal/events/auth
./internal/templates/freeradius ./internal/privileged/sources` passed again.
`goimports` applied; `golangci-lint run` reports 0 issues; `git diff --check`,
shell syntax and Python compilation passed. Go toolchain is 1.27.1. The host
`tests/radius_integration.py --native --container cloud8021x-daemon-fr-c7d492`
entry point was itself exercised with real main/legacy gates. It checks exact
fully-configured family, explicit fixture label and absence of host ports.

## APIs and remaining ownership for Tasks 7/8/9/10

Task 7: `native.ObserveSpool(directory, now)` returns bounded file count, bytes,
oldest age and available filesystem bytes via directory metadata only. Native
write/replay failure counters must come from native status/log observations;
an empty directory is not a fabricated delivery-success counter. `auth.Reader`
returns imported count/error and preserves backlog. Telemetry uses structured
event projection; native debug logs with TLS material are development-only.

Task 8: `native.Render(config.Config, generation)` returns filename->bytes and
reads protected local credential references; never opens PG/vendor connections.
Install an unpredictable per-render generation and protected file ownership,
all seven matched packages, proof root, private leaf/handoff directories, narrow
sudo helper rule and dedicated event/spool groups. Use `native.Environment` for
root-start/drop-UID startup. Supply actual fixed `sources.Radius` and Firewall
adapters. Native bootstrap/config apply remains outside this task's product CLI.

Task 9: build SourceTrust via `policy.FromConfig`; call
`LocalService.RefreshSources` on its own scheduled worker after publication,
outside request processing. Construct auth.New with producer UID/event GID,
Task3 Store and `auth.Enricher(cfg,key,snapshotStore,networkStore)`; no live
enrichment calls. Supervise retention/cursors/health, consume proof-generation
references above, and enforce HA maintenance gating for changed WAN/client/config/
secret bytes that need a restart. The same source configuration builder is used
by root rendering and the local policy resolver; do not split authority.

Task 10: preserve signed source chain, packaging rebase and two native patches;
build/sign exact target-architecture families in CI, install and validate the
actual matched artifacts. Existing Terraform/Python deployment wiring remains
until the planned installer/release migration; this task does not silently
replace production bootstrap. Review/add lifecycle tests with the real Task8/9
installed service/firewall/HA adapters and backup/restore topology.

## Honest buffer guarantee and fixture disposition

No fsync was added to per-packet detail writes, no spool replication exists, and
failed partial writes are not rolled back. ACK proves successful native buffered
write/close, not power-loss durability or zero loss. Local disk loss, power loss,
partial tails and post-rename uncertainty remain observable recovery boundaries.
PostgreSQL outages retain native files and final-auth files; limits/retention
must be monitored and coordinated by Tasks 7/8/9. No component claims end-to-end
exactly-once receipt; shared ledger dedup handles replay duplicates after intake.

Reserved native fixture retains the authenticated sources, full matched build and
logs for independent review. Native server/policy processes are stopped between
gates. The uniquely labeled own PostgreSQL fixture is
`cloud8021x-task6-pg-c7d492`, internal port only, synthetic credentials, no host
ports; it is retained stopped for controller review and can be restarted or
removed after review. No unrelated fixture was touched. The temporary networkless
loaded-module observer was removed automatically.

## Review fix round 1 — base dbe4ba08743e378186a6b1bf2acb9a0fecc86b10

Addressed all three Important findings in
`/private/tmp/cloud8021x-task6-review/report.md`, plus the orphan `ParseCounter`
comment. No native C/source/package change or rebuild was necessary. The same
fully configured `3.2.10+dfsg-2~bookworm+campus3` fixture family was used.

### Decoder and common final-auth context

Native REST value arrays now allow 200 entries, matching the native packet
attribute bound. The HTTP body limit and native `max_attributes = 200` are
unchanged. Decoder/policy tests preserve all 65/190/200 duplicate numeric values,
require verified authentication with signed Class and no VLAN, and reject 201.
The identical final accept/reject metadata construction now lives in the single
`final-auth-context` Go template definition. The separate final outcome and
observational auth-detail failure behavior are unchanged.

RED before the decoder change:

```
go test -overlay /private/tmp/cloud8021x-task6-review/overlay.json -run '^TestReviewNativeAmbiguousNASPortTypeCount$' ./internal/adapters/freeradius/policy
go test ./internal/adapters/freeradius/policy -run '^TestNativeHighCountDuplicatePorts'
docker exec cloud8021x-daemon-fr-c7d492 python3 /task6-native.py ports
```

Both Go checks failed with `invalid native attribute type or count`; the real
65-port EAP exchange returned Access-Reject. After rebuilding/copying the Go
fixture and rendering the actual templates, the exact overlay passes and `ports`
passes 65 and 128 duplicate types with Access-Accept, signed Class and no tunnel
attributes. The same mode verifies trusted client/location/source, original
receipt, exact port/station counts and forbidden-field redaction on accepted
requests and an unknown-certificate Access-Reject. An initial 190-value native
packet attempt correctly failed at the unchanged packet bound: fragmented EAP
raised the total to 204 attributes (native log: `received 204, max 200`). The
committed packet test uses 128 to leave protocol headroom; unit coverage retains
the 200/201 decoder boundary. Native textual list expansion need not have the
same length as the source list; the independently logged exact occurrence count
preserves ambiguity (observed 65/128 counts even when emitted lists were shorter).

### Replay gate now asserts delivery

The development harness adds a bounded SQL poll using the fixture's verified-TLS
`psql` connection, plus exact checks for session/status, original receipt,
transport source, configured client/location, packet ID/authenticator and replay
ID. `outage` creates a unique session, requires all three retained statuses, and
saves `/task6/replay-expectations.json` plus untouched native detail records.
`replay` requires exactly one matching intake row per retained identity and no
matching pending detail work. `replay-duplicate` additionally submits the same
native records, requires two intake copies, runs the real Go ledger processor,
and requires one shared observation and one outbox item per replay identity.
Every ACKed accounting packet in the main mode now needs its actual matching
intake row, original context/receipt and drained pending work. These are
development-only probes, not a Go accounting parser or an installed Python hook.

RED: `python3 -m unittest discover -s tests -p test_native_replay_gate.py`
initially failed all four negative regressions against the old sleep-only mode:
DB down, absent expected rows, changed receipt, and undrained matching work all
incorrectly returned success. GREEN: all six committed tests now pass, including
positive exact delivery and an ACK-without-intake failure regression.

Actual disposable native checks, in order:

```
docker exec cloud8021x-daemon-fr-c7d492 python3 /task6-native.py outage
docker exec cloud8021x-daemon-fr-c7d492 python3 /task6-native.py replay
docker start cloud8021x-task6-pg-c7d492
docker exec cloud8021x-daemon-fr-c7d492 python3 /task6-native.py replay-duplicate
docker exec cloud8021x-daemon-fr-c7d492 python3 /task6-native.py test
```

With PG stopped, `outage` retained all three ACKed records for unique session
`outage-0f60649b77d95559`. The subsequent `replay` exited 1 immediately with
connection refused, as required. After PG recovery, `replay-duplicate` passed
the exact retained metadata, pending drain and shared-ledger/outbox assertions.
A separate negative native check temporarily replaced one expected replay ID
with 64 zeroes, ran `replay`, required nonzero exit plus `replay row count`, and
restored the original manifest in `finally`; it passed. Thus an available DB
with missing expected rows cannot produce an elapsed-time success either.

The revised main mode passed all ten accounting delivery assertions for suffix
`-b1c37edd857066f0`: Start/Interim/Stop, quote/backslash/Unicode and duplicate
session/Class fields, unknown/missing status, missing/duplicate counters, NAS
IPv6, and accounting during policy outage. Its EAP rejection/resumption/outage
and final-log redaction assertions also passed with the shared template.

### Final checks and interface implications

Go 1.27.1; `goimports` applied to changed Go files. These checks passed:

```
go test -race ./internal/adapters/freeradius/policy ./internal/adapters/freeradius/native ./internal/templates/freeradius
go test -overlay /private/tmp/cloud8021x-task6-review/overlay.json -run '^TestReviewNativeAmbiguousNASPortTypeCount$' ./internal/adapters/freeradius/policy
python3 -m unittest discover -s tests -p test_native_replay_gate.py
PYTHONPYCACHEPREFIX=/private/tmp/task6-fix-python-cache python3 -m py_compile tests/native_radius_container.py tests/radius_integration.py tests/test_native_replay_gate.py
golangci-lint run
git diff --check
```

Lint reported `0 issues`. Initial sandbox-only lint/overlay/Python-cache attempts
could not access caches; reruns with the required cache access or temporary Python
cache passed. No dependency tidy or unrelated source change was made.

No exported product API/schema change. The test CLI adds `ports` and
`replay-duplicate`; replay now requires an `outage` manifest and `psql` in the
development container. A fresh outage is required before each independent replay
scenario because already duplicated records intentionally fail the one-copy
precondition. README documents these prerequisites. All previous Task 8/9/10
installation, lifecycle, release and buffer-durability boundaries remain in force.
Native/policy processes are stopped between modes, and the task-owned PG fixture
was returned to stopped state with `docker stop cloud8021x-task6-pg-c7d492`.

## Review fix round 2 — base f5b6a45a76698fd10ae4a52316274da50e18d755

Addressed the remaining Important 2 assertion gap identified in
`/private/tmp/cloud8021x-task6-fix-review/report.md`. The previous duplicate gate
allowed the three distinct Start/Interim/Stop reports to collapse into one ledger
observation because its expected count came from the observed IDs. The corrected
development-only gate validates the three-status fixture, requires a distinct
nonempty observation for each of its three expected replay identities, and checks
observation/outbox counts against the manifest identity count. Each pair of
duplicate intake copies must still share the same observation. This expectation
is specific to these three distinct semantic reports; no product semantic dedup
or uniqueness rule for legitimate NAS retries/different native IDs was changed.

RED, before changing the gate:

```
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_native_replay_gate.py
PYTHONDONTWRITEBYTECODE=1 python3 /private/tmp/cloud8021x-task6-fix-review/cross_identity_gate_probe.py
```

The new `test_duplicate_gate_rejects_distinct_status_reports_collapsing` failed
with `AssertionError not raised` (nine tests, one failure). The supplied probe
exited 1 after the gate falsely printed success for one collapsed observation
and one outbox item. GREEN after the fix: the exact same commands pass; all nine
tests succeed, and the supplied probe reports `PASS: duplicate gate rejected
cross-identity collapse`. Covering tests also require both expected table counts
and accept three distinct observations with deduplicated copies.

Only the changed actual native scenario was rerun, without rebuilding Go or the
unchanged native package family:

```
docker cp tests/native_radius_container.py cloud8021x-daemon-fr-c7d492:/task6-native.py
docker exec cloud8021x-daemon-fr-c7d492 python3 /task6-native.py outage
docker start cloud8021x-task6-pg-c7d492
docker exec cloud8021x-daemon-fr-c7d492 python3 /task6-native.py replay-duplicate
docker stop cloud8021x-task6-pg-c7d492
```

Fresh session `outage-1da235e7f4a50c57` produced three ACKed, retained status
records with the disposable database stopped. After recovery, `replay-duplicate`
exited 0: exact original receipt/source/replay identities survived, matching
pending work drained, two intake copies per identity shared their observation,
and the three distinct reports produced three observations and three outbox
items. The disposable database is stopped again; native/policy processes exited
through the existing harness cleanup.

`PYTHONPYCACHEPREFIX=/private/tmp/task6-fix-python-cache python3 -m py_compile
tests/native_radius_container.py tests/test_native_replay_gate.py` and
`git diff --check` passed. No Go files, exported APIs, native packages, product
ledger behavior, or installation/lifecycle boundaries changed in this round.
