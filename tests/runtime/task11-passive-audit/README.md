# Task 11 installed passive observer

Development fixture only. The shipping CLI, accounts, PAM, packages, APIs and
activation guards are unchanged. No installed execution or reboot proof has yet
been performed by this helper. Pure tests and cross-builds cannot close those gates.

## Fixed interface

Install the reviewed Linux executable root:root 0755 at
`/usr/local/libexec/task11-passive-audit`. The controller calls exactly:

```
/usr/local/libexec/task11-passive-audit observe
```

There are no command, path, endpoint, credential or phase flags. Strict JSON on
private stdin is bounded to 16 KiB; unknown/duplicate fields and extra documents
are rejected by the production decoder. All JSON names are the exported CamelCase
Go field names in `contract/types.go`. Request fields are:

| Name | Required value/source |
| --- | --- |
| Schema | 1 |
| Node | green-primary or green-secondary |
| Phase | prepared or deactivated |
| MachineID | enrolled 32 lowercase hex machine ID |
| Pin | enrolled Ed25519 public key, 64 lowercase hex |
| BootID | pre-observed actual boot UUID for this invocation |
| Namespaces | exactly mnt, pid, uts, net, cgroup and actual `name:[inode]` identities |
| ApplicationSHA256 | installed clean application hash |
| ApplicationSourceSHA | installed application's clean 40 hex VCS revision |
| ConfigSHA256 | exact installed/staged configuration bytes hash |
| ControllerSHA256 | exact installed acceptance executable hash |
| ObserverSHA256 | exact reviewed installed observer executable hash |
| SeedSHA256 | exact independent protected manifest bytes hash |
| OriginalSeedSHA256 | immutable original source bundle manifest hash; distinct from cloud API seed hash |

The controller owns enrollment, namespace FD/cgroup transport, private stdin,
actual reboot orchestration and before/after comparison. Request boot/namespaces
must be freshly obtained for each genuine boot. The observer checks its own and
PID1 namespaces against those expectations and verifies actual systemd PID1,
start time, boot ID, machine ID and hostname. It derives the actual node public
key from the existing protected private key, verifies internal seed/public-key
consistency, compares Pin, and clears key buffers. It never signs or creates keys.

Successful collection returns one typed `contract.Result` JSON document bounded
to 256 KiB. There is no pass marker, signature, authorization or activation bool.
Errors produce no result and nonzero exit. The context deadline is 45 seconds;
systemd probes have five-second deadlines and 32 KiB output limits enforced by
a named private buffer through the actual io.Copy/subprocess pipe route, SQL has a
15-second deadline. The controller must also bound the observer's process cgroup
and reject timeout, missing output, malformed output or failed cleanup.

## Independent preserved-state manifest

Before execution, the controller installs root:root 0600
`/etc/cloud8021x-task11-passive-seed.json`, with exactly:

```
{"Schema":1,"OriginalSeedSHA256":"...","CertificateStateSHA256":"...","Slots":{"ec-root":"...", "...":"..."}}
```

Every digest is lowercase SHA256. This is independently pinned expected input,
not observer-generated success metadata. The controller must derive each installed
slot from the genuine protected production preparation/adoption/render output,
bound to the immutable original source bundle. Do not blindly copy source path
hashes: installed client trust concatenates intermediates and roots; installed
inventory may be normalized by adoption. CertificateStateSHA256 covers the actual
original certificate-state bytes carried by the genuine source handoff, also
bound to that original source provenance. API seed hashes alone are insufficient.
There is no arbitrary path map in the request or manifest.

Closed Slots (all 24 are mandatory; no extras):

| Slot | Actual installed path | UID:GID / mode |
| --- | --- | --- |
| ec-root | /etc/step-ca/certs/root_ca.crt | root:root / 0600 |
| ec-intermediate | /etc/step-ca/certs/intermediate_ca.crt | root:root / 0600 |
| ec-decrypter | /etc/step-ca/certs/scep_decrypter.crt | root:root / 0600 |
| ec-decrypter-key | /etc/step-ca/secrets/scep_decrypter_key | root:root / 0600 |
| ec-config | /etc/step-ca/config/ca.json | root:root / 0600 |
| ec-template | /etc/step-ca/templates/x509/wifi-acme.tpl | root:root / 0600 |
| rsa-root | /etc/step-ca-rsa/certs/root_ca.crt | root:root / 0600 |
| rsa-intermediate | /etc/step-ca-rsa/certs/intermediate_ca.crt | root:root / 0600 |
| rsa-decrypter | /etc/step-ca-rsa/certs/scep_decrypter.crt | root:root / 0600 |
| rsa-decrypter-key | /etc/step-ca-rsa/secrets/scep_decrypter_key | root:root / 0600 |
| rsa-config | /etc/step-ca-rsa/config/ca.json | root:root / 0600 |
| rsa-template | /etc/step-ca-rsa/templates/x509/wifi-scep.tpl | root:root / 0600 |
| native-server | /etc/freeradius/3.0/certs/server-cert.pem | root:native GID / 0640 |
| native-server-key | /etc/freeradius/3.0/certs/server-key.pem | root:native GID / 0640 |
| client-trust | /etc/cloud-8021x/client-cas.pem | root:root / 0644 |
| server-cache | /etc/cloud-8021x/radius-server.pem | root:root / 0644 |
| webhook-cache | /etc/acme-authz-webhook/server.crt | root:root / 0644 |
| webhook-cache-key | /etc/acme-authz-webhook/server.key | root:root / 0600 |
| webhook-public | /etc/cloud-8021x/webhook.crt | root:root / 0644 |
| webhook-key | /run/cloud-8021x/credentials/webhook.key | runtime UID:GID / 0600 |
| class-key | validated protected cfg.Policy.ClassSigningKey.File | runtime UID:GID / 0600 |
| legacy-class-key | /run/radius-accounting-key | runtime UID:GID / 0600 |
| inventory | /var/lib/cloud-8021x/inventory.json | runtime UID:GID / 0644 |
| postgres-ca | /etc/cloud-8021x/postgres-ca.pem | root:root / 0644 |

The observer checks descriptor-walked non-writable protected ancestors, exact
regular-file owner/group/mode, one hard link, bounded lengths and unchanged
metadata during reads. Symlinks and unknown ownership refuse. Certificate/key
pairs must match; Class bytes must equal the preserved legacy key; PostgreSQL
trust must match the actual authenticated artifact manifest. Private content is
never returned: only SHA256 and metadata. Production KnownInstallation,
CommittedCredentials and ParallelInstalledReceipt bind cache, restored boot
credentials, completed physical generation and prepared SQL receipt. The volatile
credential marker must match the completed cache/reference; no restore API runs.

## Actual passive predicates

Eight guarded mutating services are observed separately: daemon, FreeRADIUS,
both step-ca authorities, root renew and sources services, Agent and DDOT. Their
actual protected barrier bytes come from `host.ParallelPassiveFiles`, installed
unit bytes from `systemd.Render`. Prepared services must be loaded/inactive/dead,
MainPID=ControlPID=0, known reported last condition result and exact fixed drop-ins; the native
service has both cloud8021x.conf and parallel.conf. No foreign overrides are allowed.
Both activation artifacts must be absent with protected parents, proving the
fixed ConditionPathExists predicate is currently false. ConditionResult is the
last evaluation and may retain yes; it is not substituted for current guard
evidence or product activity. Timer observations
use the timer/unit property interface; service-only PID/cgroup fields are not
queried on timers and their typed zero values are not service-process evidence.

Prepared renew/sources timers may be disabled/inactive or enabled/active/waiting
only with their exact guarded service target, protected shipping fragment
`/etc/systemd/system/cloud-8021x-renew.timer` or
`/etc/systemd/system/cloud-8021x-sources.timer` fragment, and no timer drop-ins. Foreign or missing
fragments and any timer override refuse in both waiting and inactive states.
Timers are not assumed universally
inactive. Deactivated daemon/renew/sources services and both timers must instead
have the genuine protected persistent /dev/null masks. The actual production
VerifyDaemonWorkerFence verifies preserved unit receipt, completion, old process
retirement and native quiescence; its digest must equal the own-role SQL fence.

Bounded actual `/proc` observations reject daemon, native, authority and monitoring
processes, their known command identities, configured admission listeners across
IPv4/IPv6, native/control/CA/metrics/collector ingress ports, and live cloud or
metadata API peer sockets. Kernel observations are repeated after SQL; boot/PID1
identity must remain unchanged. These are snapshots, not historical evidence of
all outbound activity: the shared cloud journal's peer audit must independently
cover the entire passive window. No assertion here substitutes for that audit.

The collector must be a unique ext4 loop mount on the product's protected 512 MiB
image, rw/nodev/nosuid/noexec, with actual fixed sysfs backing path, ext4 superblock
UUID and bounded statfs capacity. Mutable filesystem contents are not hashed or
written. Result.Collector.Image has metadata and deliberately no SHA256; the
controller compares preserved filesystem UUID/backing path/size and protected
identity, allowing mount device numbers to change with a reboot.

SQL uses only the protected fixed synthetic migration DSN, host 10.203.11.11:5432,
database cloud8021x_task11_green, role cloud8021x_task11_green_migrate, production
verified TLS and no fallback. It explicitly verifies actual READ ONLY repeatable
read, never acquires a writer/advisory lock, and executes only source-fixed SELECTs.
It returns actual epoch/transition, enabled/blocked/workers_allowed, both original
writer fences, both real prepared receipts/import bindings, readiness, and bounded
SHA256/count snapshots of work, attempts and original legacy collection guards.
Source authorization Class/trust/certificate identity and original writer-fence
receipts must match; raw authorizations, payloads and credentials stay private.
This observes the already verified import. It does not fabricate or re-verify a
fresh signed envelope from the persisted public subset or relax capture freshness.
Prepared requires disabled/unblocked/not-ready, zero worker fences. Deactivated
requires disabled/blocked and both completed worker fences. Ready may retain the
actual prior activation flags on deactivation, while workers_allowed remains false.

## Controller comparison and remaining actual gates

Before/after genuine reboot: MachineID, Hostname, enrolled Pin, app/source/config,
controller/observer/seed/original hashes, all preserved slot SHA256, completed cache
and generation hashes, filesystem UUID/backing image identity, and durable SQL
work/attempt/guard/authorization/fence/preparation hashes must remain unchanged.
BootID must change; namespace inodes, process PIDs/start times, /run file inodes and
mount device numbers are observations that can change. Do not compare ephemeral
identities as preserved content or mistake a changed boot UUID for a reboot unless
the controller actually performed and observed the enrolled machine reboot.

Still required: independently derived/pinned manifest, reviewed source/binary
pins, actual both-green prepared installed-node runs, genuine reboot orchestration
and comparison, passive cloud-peer journal audit, final prepared readiness and
passive recheck before first real activate, and genuine deactivated runs/fences.
R123 permits API permissions only in its later permission-ready window; permissions
are never product activation proof. Real CLI/DB/PID1 workers-active proof and intake
release belong to the controller's subsequent acceptance stages.
