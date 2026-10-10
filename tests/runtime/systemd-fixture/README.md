# Real PID1 development fixture preparation

**R99 blocker:** the retained R99 binary must not be reused for another resume.
It read stale raw dpkg status and missed pending journals. Current source now
uses a fresh bounded authoritative `dpkg-query` for both gates and passes actual
journal integration regressions. No corrected VM stage has run. Controller
review and a new resource grant remain required; see report sections K/L and
`fresh-nested-stage-plan.md`. No man-db or later-transaction exception was added.

This directory contains development tools, not product service replacements.
`systemd-fixture` audits real installed services and records bounded JSON;
`--previous` requires a changed same-node boot ID and unchanged installation
artifact hashes. It checks PID1, private-guest marker, no default routes,
cgroup2, absence of host shares, installed unit process/cgroup identity and,
when active, the genuine shipping ext4 loop mount/backing file/options.
It never creates a product activation marker or success receipt.

`systemd-fixture packets --plan FILE` uses `eapol_test` only as a NAS, observes
unmodified authenticated RADIUS replies, checks numeric Tunnel-Type13 and
Tunnel-Medium-Type6 plus VLAN and signed Class, then sends authenticated
Start/Interim/Stop with bounded counters. It targets only `10.203.11.21` or `.22`
from reserved NAS `.40`, requires an installed-service audit for the target,
and never starts `freeradius -X`, a native fixture, or rewrites configuration.
Its ACK evidence still requires independent exact SQL/replay/collector checks.
The generation/parsing conventions are adapted from the existing native
packet fixture, without importing that fixture's process/config side effects.

The packet plan fields are `target`, `source`, `secret_file`, `eap_config`,
`installed_evidence`, numeric `vlan` (0 means no VLAN), optional `expect_reject`,
and new exclusive `output`. All input/output files must reside beneath the
owned guest `/var/lib/cloud8021x-task11/`. RADIUS secrets are synthetic and
start with `task11-`. The operator transfers the target's audit through the
owned authenticated fixture control channel before packet execution.

## Verified outer platform and remaining nested-node canary

OrbStack is rejected for loop ownership because its kernel is shared. Root
ruling85 permits the dated official Debian13 generic ARM64 image authenticated
via HTTPS and pinned SHA512 (no detached signature was published):

- `https://cloud.debian.org/images/cloud/trixie/20261001-2618/debian-13-generic-arm64-20261001-2618.tar.xz`
- Compressed SHA512: `cb80554bf05aa9eb42d0b99a9a395fefad04edc8435514c5387e32f4da83b7827c34809f6249b365dedacd3f0688580f2957fd13b388639c987058bbe127fa8d`
- Raw SHA512: `bfaff28606ee833aef5b42cc057105cf0c6d59137d0198492ecd46ec5afc36c998860d020207f71752343230a552dc81c73b27d583bacb11ad961bc452eed992`

The compressed300,969,928-byte image and its sparse3GiB raw image both passed
those hashes. The real zero-NIC VZ outer guest subsequently passed PID1, live
ABI, independent kernel, cgroup2, owned ext4 loop mount and reboot persistence.
This is outer-platform proof, not installed-app or nested-node acceptance.
The reviewed resource ceiling is one owned Tart VM,2CPU/3072MiB, sparse8GiB
logical disk, measured allocated growth; `TART_NO_AUTO_PRUNE=1` on every Tart
operation. No host shares, exposed ports, credentials, trust or engine changes.

Future seed construction uses the three checked-in cloud-init templates named
`user-data`, `meta-data`, `network-config` in a new owned directory; existing
macOS `hdiutil makehybrid -iso -joliet -default-volume-name cidata -o SEED.iso
SEED_DIR` creates the read-only seed. No host package installation is required.
The outer is serial-controlled, with no guest agent/SSH requirement. The network
seed disables addresses and the early boot command drops every non-loopback
interface and forwarding. Initial canary prints only environment/prerequisite
facts on `/dev/hvc0`; it does not launch product/cloud clients.

Historical Tart commands (created/configured; `run` failed before boot):

```sh
TART_NO_AUTO_PRUNE=1 tart create --linux --disk-size 8 cloud8021x-task11-owned
TART_NO_AUTO_PRUNE=1 tart set cloud8021x-task11-owned --disk VERIFIED_RAW --cpu 2 --memory 3072
TART_NO_AUTO_PRUNE=1 tart set cloud8021x-task11-owned --disk-size 8
TART_NO_AUTO_PRUNE=1 tart run cloud8021x-task11-owned --net-host --no-graphics --no-audio --no-clipboard --serial --disk SEED.iso:ro
```

The dedicated image is a full ARM64 kernel6.12.111-1 and already has matching
systemd257.13, sudo1.9.16p2, libc2.41, libssl3.5.7 and perl5.40.1. It lacks
systemd-container, PostgreSQL and eapoltest. The separately authenticated26-archive
snapshot20261008 development closure is pinned in `dev-prerequisites.lock.json`;
signed index verification, archive hashes/identities and exact live base321
package inventory all passed. Its offline installation was interrupted; the
single600s resumption refused a pending baseline trigger before continuation.
See the full preparation report for preserved failed-stage evidence; nested
PID1/loop/reboot remains unproved. Never append development
packages to the shipping62 or run online apt on product nodes.

Private inner topology is one unrouted `10.203.11.0/24` bridge, greens .21/.22,
synthetic source nodes .31/.32, provider .10, PG .11 and NAS .40; no bridge
address or route on the outer NIC. Per-namespace IPv4/IPv6 default-deny rules
allow only this exact endpoint set and node-local metadata. Actual nspawn
PID1/cgroup delegation, loop ownership, one-node reboot and zero forwarded
listeners must be proved before full four-node assembly. No privilege/device
workaround may reach the Mac or Orb kernel.

## Remaining whole-flow gates

Source seeding and real four-pin enrollment/capture/prepare/activation/reversal
are not implemented by these probes. They must run the documented shipping CLI
in order, with protected real root-signed receipts and real TLS PostgreSQL.
Then execute passive reboot/start-barrier refusals, live EAP/auth/accounting,
first-ongoing baseline0, stale inventory/downgrade, PG outage/replay and collector
queue/reboot recovery. Deactivate both nodes, prove actual persistent fences,
exercise missing-fence and unresolved-command rollback refusal, reconcile exact
terminal work, transfer both genuine proofs and resume only synthetic sources.
No passing primitive/unit/probe is a substitute for that acceptance chain.

The supported owned host runner is now `zero-nic-vm.swift`, not Tart networking.
Tart2.32.1 `--net-host` invokes Softnet and failed for unavailable privileges;
no sudo/setuid/host-network change was attempted. Root ruling88 authorized the
small VZ alternative. Compile with existing `xcrun swiftc -j1 -module-cache-path
OWNED_CACHE zero-nic-vm.swift -o OWNED_BINARY`, then ad-hoc codesign using only
`zero-nic-vm.entitlements`. Its three arguments are owned disk, read-only seed
and owned EFI. It has physically0NIC/0socket/0share devices, serial output only,
CPU2/RAM3GiB, a maximum16GiB task-owned disk and a240s default canary deadline; the optional fourth argument
`600` is reserved for an explicitly approved bounded installation stage. No new host trust or installed helper. The full four-node assembly requires at least5,570,035,712 bytes free after prerequisites and staged inputs; the prior8GiB canary disk does not meet that admission. Use a fresh task-owned disk, preserving the canary disk and evidence unchanged. The larger disk ceiling does not waive measured capacity or any assembly check.

The final seed logs first-boot ID, requests a real reboot, verifies a different
ID and retained loop-file contents on the second boot, then powers off. Its
loop image is a16MiB platform capability probe; it does not replace or claim
proof of the actual shipping collector's512MiB mount. Before further use, see
the full A–I preparation report in the task scratch directory for evidence,
authorized resources and remaining acceptance gaps.

## Offline nested platform stage

`offline-prereq-canary.sh` is a guest-only platform probe, not product bootstrap.
Attach a read-only NoCloud ISO containing `cloud-init-nested-user-data.yaml` as
`user-data`, a unique `meta-data` instance ID, the exact approved development
archives under `archives/` using ISO-safe names `p000.deb` through `p025.deb`,
lowercase `archives/sha256sums` with those names and unchanged locked hashes, and independently
verified baseline evidence. The next reviewed seed must also contain the exact
pinned original `guest-dpkg-status` as `base.txt`, the approved lock JSON as
`dev.txt`, the built development helper as `fixture`, and its SHA256 line in
`fixture.sum` (ISO-safe filenames). No seed or VM has been updated/launched
with this recovery guard yet. The previous v4/v5 artifacts remain unchanged.
The script refuses a mismatched base or archive and blocks package service
starts. It creates one guest-only overlay root, an unrouted private bridge and
namespace firewalls, then exercises actual nspawn PID1, cgroups, an owned loop
mount, and container reboot. Its exit trap powers off the outer VM.

Preserve serial output and verify the final pass marker as well as each earlier
assertion; runner exit zero only means the VM powered off. A failure is not an
application acceptance result. Neither this probe nor its seed installs the
shipping app or activates any application role.

The proposed later whole-flow sequence is in `full-acceptance-design.md`. It is
not execution evidence, and final reviewed product bytes are still pending.

### Interrupted prerequisite recovery review

`prerequisites.go` replaces the previous inline status check with a read-only
Go guard. It pins all321 original package versions **and architectures**, the
exact26 archive lock, every short-named archive hash/size, and the saved original
baseline. An archive glob cannot introduce an unapproved extra file. Before
resumption, only the actual v4 unpack states are permitted. The sole baseline
exception is `libc-bin` pending exactly `ldconfig`, with no awaited links, an
approved library actually present, a pinned archive control declaration of
`activate-noawait ldconfig`, and ordered dpkg log attribution within the exact
owned interrupted window. Unknown pending/awaited triggers, replacements,
other transactions or missing lineage fail closed. No baseline awaited trigger
is currently authorized. This narrower rule may still refuse an additional
unobserved pending package; that would require evidence and another review.

After offline dpkg, `prerequisites --final` requires the exact321+26 identities,
every status fully installed, no pending/awaited triggers and literally empty
`dpkg --audit`. It runs before any private bridge or nspawn command. The real
v5 refusal was reproduced red before this change; focused adversarial tests,
the authenticated baseline/archive inventory test, and lint are the source
review gates. They do not prove guest resumption or nested operation.
