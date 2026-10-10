# R145 fresh journal-observed installer proposal — held

Source review and preparation/launch grants are required before execution. No
new seed, clone, helper build, VM, package action or recovery is performed here.
This proposal preserves the existing minimal nested canary; it does not assemble
four product nodes or authorize source capture, CA, API or product activation.

## Why this change, and what remains unknown

R105's retained host serial log is 23,353 bytes, ending with getty terminal
sequences/login and the host watchdog. The frozen Swift runner connects serial
to its stdout, retained as a regular file; no head/pipe truncator is present in
that runner. Retained supervisor/result metadata reports the real 600-second
watchdog, but cannot reconstruct missing guest stderr. R143 subsequently proved
that the service exited with status 1 after 5.854 seconds and the crash-view dpkg
log advanced through PostgreSQL 17 unpacking. This supersedes the old inference
of a running Perl-unpack stall; it does not identify the failing command/cause.

The original shell redirected both streams to `/dev/hvc0` before registering an
EXIT trap. The trap itself wrote to that same console before requesting shutdown
under errexit. Tests demonstrate lost stderr/status and skipped shutdown when
that sink cannot open or has a broken pipe. This is a proved harness weakness,
not proof that the same failure caused R105.

## Narrow source contract

- Leave command stdout/stderr on the service journal, explicitly configured with
  `StandardOutput=journal` and `StandardError=journal`. Disable only this unit's
  journal rate suppression; the existing guest journal retention remains bounded
  by `SystemMaxUse=32M` and `RuntimeMaxUse=16M`. No host journal/settings changes.
- Emit trusted fixed phase begin/end records. On failure, retain the actual shell
  exit status and active phase in the journal. No child stderr redirection away
  from the journal; no installer pipeline that could substitute a consumer exit.
- The EXIT handler disables errexit only for reporting/cleanup, synchronizes the
  journal with a 10s+1 bound, queries only the current boot/fixed service with a
  separate 10s+1 bound, and exports at most 262,000 bytes plus a fixed frame
  (under 256 KiB) to serial. A 262,001-byte spool detects truncation. Query failure
  or truncation is explicitly reported and is not successful diagnostic export.
- Serial open AND write occur inside a 10s+1 child timeout. Even a failed/blocked
  serial export or journal query cannot skip the separate bounded shutdown request.
  Original command exit status is preserved; export/shutdown statuses are separate.
- Existing service `TimeoutStartSec=440` and the proposed host600s hard deadline
  remain; diagnostic time does not extend either. Journald retention may rotate
  old records under extreme output: missing/truncated evidence is inconclusive,
  never acceptance. Real service-journal behavior still needs the next guest run;
  host tests use synthetic journal/systemctl commands and owned sinks.
- Removing only added phase-label calls leaves the entire original installer/body
  byte-identical, including exact archive hash/ordering, `dpkg --install` argv,
  fresh effective321 guard, audit-empty/final347 gate and all later namespace,
  cgroup, private-network, loop, copy-cap and reboot checks. No package ordering,
  dependency, maintainer-script, trigger or recovery exception is changed.

## Proposed separate preparation

1. Fresh capacity >=5.5 GiB; no competing heavy build/VM/acquisition. Retain all
   original/R105/R136/R139/R143 disks, EFI, logs and authenticated caches unchanged.
2. After a preparation grant, use exclusive owned0700
   `/private/tmp/cloud8021x-task11-debian-20261001.d5B0lJ/fresh-journal-installer-r145`.
   APFS-clone the authenticated original3,221,225,472-byte image, sparse-extend ONLY
   the new clone to8,000,000,000 bytes, use fresh own original131072-byte EFI. Prove
   distinct inodes, official SHA512 of the original prefix and zero sparse suffix;
   no clone of a failed/interrupted root and no evidence attachment to this VM.
3. Keep R105's exact frozen helper b7eeabebca8d7f8a24ee9597b3ca9f7b35355d7a455610de722acc815b4191b0,
   original321 base.txt and exact26 ac9c459f lock/archives. Preserve p000–p025 names,
   order and digests. No new package, resolver, helper build or acquisition.
4. Build a new read-only NoCloud seed from the retained R105 seed inputs, replacing
   only the reviewed canary script and nested user-data service I/O settings.
   Meta/network/fixture checksum/base/dev/26archives remain exact. The prior seed
   was76,169,216 bytes; cap the new seed at80MiB. Verify both ISO payload views,
   every hash, full user-data, original inputs before/after, ownEFI and runner.
   Freeze actual inventory/seed hash for root review before any launch grant.

## Proposed one separate actual run

Use unchanged frozen zero-nic-vm runner SHA256
`4225b5b610ab60bf9ae1f17a9e9e603c6a93945b647bf6c6cac2233d8b27e5d8`,
exact fresh boot/seed/EFI arguments plus its existing `600` argument. Ordinary VZ
permission context only, 2CPU/3GiB/8GB, zero NIC/socket/share/listeners/host settings.
Capture the whole runner output directly to a new exclusive regular log.

Take a fresh >=5.5GiB baseline immediately before launch. Sample once per second;
stop only the owned process group at max(baseline minus3.5GiB,2.5GiB), protecting
2GiB reserve. This is a conservative host-wide delta, not APFS owned-allocation
proof. Existing guest bounds stay source<=1.5GiB, sparse stream<=1.625GiB,
lower<=1.75GiB, >=3GiB guest free before copy and >=1GiB afterward. Guest journal
32MiB retention and <=256KiB export spool fit inside the existing resource budget.
No product payload or four-node layer is included.

Require actual fresh321 and archive checks before install; all exact347 installed
and empty audit before bridge/nspawn. If those pass, only the already defined
minimal nested PID1/cgroup/private namespaces/16MiB loop/real reboot-persistence
canary may follow, subject to the explicit next run grant. Do not infer those
proofs from successful package installation or service/launcher exit.

Retain phase/error/actual-exit frames, journal export query/truncation status,
shutdown status, full host log/capacity/process-retirement and final own-disk/EFI
hashes. A failed or lost serial export means evidence is incomplete even if the
VM powers off; preserve the new disk and stop for a separately reviewed read-only
retrieval. No automatic retry, repair, journal replay, trigger exception, audit
weakening or extension. Root cause remains unknown until actual error evidence.
