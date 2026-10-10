# Protected green installation and recovery

The supported rollout creates a separate Debian 13 pair using `terraform/green`.
It adopts the existing step-ca material and trust, and starts a new accounting
epoch. Use [deployment sequencing](../deployment/parallel-green.md) and the
[parallel adoption workflow](../parallel-adoption.md) for the complete ordered
procedure. This document describes implementation guarantees, not approval to
provision infrastructure or switch production traffic.

## Authenticated inputs

The thin loader authenticates the metadata project and physical instance, then
stages a bounded, generation-pinned bundle under the root-private directory
`/var/cache/cloud-8021x/artifacts`. Required inputs are the application, strict
YAML configuration, artifact manifest, release provenance and exact PostgreSQL
instance CA. Every object has a mandatory SHA256. The loader never overwrites
installed application or CA files and never resolves packages on the VM.

The protected incoming operation is:

```sh
sudo /var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap prepare --incoming --dry-run
sudo /var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap prepare --incoming
```

Root commands accept only the fixed configuration selector. With `--incoming`,
it reads the fixed staged configuration through protected descriptors; arbitrary
paths and listener overrides are rejected. Go independently verifies application,
configuration, provenance, package metadata, architecture/ABI, operating system
and PostgreSQL CA pins. It consumes only the authenticated package closure; there
is no fallback package resolver or broad operating-system upgrade.

The supported components remain FreeRADIUS, step-ca and Datadog Agent/DDOT. See
[release construction](../releasing.md) for exact package versions and provenance.
The old webhook basename does not select a second runtime. All application
commands use the unified YAML-configured Go executable.

## Preserved authority and passive preparation

Green adopts the exact existing CA signers, certificate chain, decrypter, database
and provisioners. It does not initialize a replacement CA when adoption fails.
Server trust, enrollment frontdoors and Class/challenge/broker identities remain
bound to the original deployment. The authenticated source handoff preserves
original policy and certificate observation timestamps, ambiguity and pending
Fleet command provenance. Copying evidence never refreshes its age. Missing or
mismatched material fails closed.

Preparation is passive. It publishes protected files transactionally and validates
installed native configuration and preserved material, but does not authorize ordinary
shared work, renewals, Fleet submissions or production telemetry export. Both
source receipts and destination pins must match the common deployment and release.
Use `bootstrap activate` through the ordered adoption procedure to verify running
service readiness while both nodes remain isolated. NAS and EC/RSA/broker backend
changes remain separately coordinated by their existing owners.

Accounting history is not imported. The shared PostgreSQL ledger binds an explicit
collection epoch; the first report of an ongoing session establishes its baseline.
Native spool processing uses session locks, deduplication and transactional outbox
records. CA databases and privileges are separate from the application ledger.
Never give SQL administrator credentials to the VMs.

## Protected publication, boot and renewal

Go retains exact prior files, ownership, service/process state and bounded package
rollback evidence before publication. Failed or uncertain work stays quarantined;
lease expiry alone does not prove a stopped helper. An interrupted operation may
resume only its original typed attempt after proving the original process exited
and configuration, binary and retained receipts still match.

Boot restores credentials from the committed root-private cache. The daemon runs
as its dedicated unprivileged account and cannot control services, packages or
firewalls. Activated certificate renewal uses preserved CA authority, committed
credentials and the shared maintenance gate. Native activation stops the producer
before replacing its synchronous policy dependency, then checks the replacement
before releasing the persistent service fence. A reporting error after a committed
operation does not relabel it as an uncertain installation.

`bootstrap deactivate` revokes shared authority before retaining the node's physical
worker-fence and Class-bound state receipt. `bootstrap rollback-proof` requires
both physical receipts and preserved unresolved work. It does not restore blue
writers. Follow the ordered reverse handoff in the parallel adoption document;
keep blue VMs, disks, original CA state and unknown external work throughout
acceptance. The removed in-place migration and accounting archive commands are
not available.

## Validation boundaries

[The integration suites](../../tests/README.md) separately exercise PostgreSQL,
signed handoff, native EAP/accounting, CA issuance, Agent checks and Collector
persistence. Those results do not prove systemd boot/reboot, cloud KMS/IAM,
production CA adoption, two-node cutover or physical-device renewal. Those remain
staging gates before production activation. Retired implementations remain in Git
history; small independent CA/profile goldens are development-only comparisons.
