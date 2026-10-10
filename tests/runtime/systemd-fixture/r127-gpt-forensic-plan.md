# R127: preparation only; no derivative or VM created

Use a new APFS clone of retained R105 evidence. Change only its GPT disk GUID,
used partition unique GUIDs and the necessary primary/backup CRC32 fields.
Source remains immutable; no filesystem UUID, GRUB, partition geometry, type,
attributes, name, PMBR or filesystem content changes. No repair/replay/fsck/install.
This addresses duplicate boot selectors, not the unproved original dpkg stall.

## Frozen inputs and read-only computed result

Owned root: `/private/tmp/cloud8021x-task11-debian-20261001.d5B0lJ`.
- R105 `fresh-pristine-history-20261009/disk.img`: 8000000000 bytes;
  SHA256 `e35f2e3cf5bf4ab127e2f0bb2ce8d71f52e82bceb4e80680de7175e1cc366845`.
- Original `extracted/disk.raw`: 3221225472 bytes; SHA256
  `02c4d0d6812fe927e15daf323852b216efd514c0d00fb497ca84193d694c9d96`;
  official recorded SHA512 `bfaff28606ee833aef5b42cc057105cf0c6d59137d0198492ecd46ec5afc36c998860d020207f71752343230a552dc81c73b27d583bacb11ad961bc452eed992` reverified.
- Frozen rescue seed: 921600 bytes; SHA256
  `c4d2649aa2d66eaf8b4ebe7e4b9dc00751d1e10f20182dba3eae809f0d1e0206`.
- Read-only Go helper `systemd-fixture-gpt-r127`: SHA256
  `be13f5e0e188c0df3093c231f855fcb161a71f4faf43f8fc4393c10ccff2b9af`.
- Exact patches/base64 before+after bytes: `gpt-r127-plan.json` (under owned root).
- **Computed, not yet materialized** derivative SHA256:
  `d47f5e7283cde3f2e7eee5938986e24c093f918f2eb4035de5677134825beb4b`.
- SHA256 of concatenated ascending unchanged ranges (7999999888 bytes):
  `2d33780e7199e0688a37d7fb3190ec58462d93ffb1a084ed9b1c04276193b622`.

| Identity | Original boot and retained evidence | Proposed evidence derivative |
|---|---|---|
| Disk GUID | 635fd7c9-b87d-453e-970a-5fb81b96b174 | 0bd2f4d9-375a-4c48-9c4e-eb53f34c7bca |
| Partition 1 | d35a5af0-fb25-480f-ab0d-73615f73fc09 | c2fb6dc1-ec0e-496c-9172-017c4cfd3483 |
| Partition 15 | 2a86046b-16e0-4803-8df5-cb2c24a6c8a0 | c8121177-97e2-4e66-9ddb-cd146d9ef1e1 |

Original GRUB root selector is partition1's old PARTUUID, now unique across both
proposed attachments. Filesystem UUID intentionally remains duplicated; this does
not establish actual root selection, which must be observed inside the guest.

Exactly ten permitted fields, in bytes as offset:length:
`528:4`, `568:16`, `600:4`, `1040:16`, `2832:16`, `7999983120:16`,
`7999984912:16`, `7999999504:4`, `7999999544:16`, `7999999576:4`.
Total allowed field bytes112; every other byte must compare equal. All regenerated
identities must be nonzero and distinct from every old/boot/new unique GUID. GPT
partition **type** GUIDs are preserved, not treated as unique identities.

## Creation gate (not granted or performed)

After root reviews the frozen delta and exact plan: make new uniquely named APFS
clones of original boot and R105 evidence, and a fresh owned EFI copy. Before any
write, rehash all sources, check every source/clone/EFI/seed is owned regular,
canonical/non-symlink, and distinct device+inode. No reuse of booted R118 disk.
Write only the reviewed ten fields to the new derivative. Reparse both GPT copies,
verify CRCs/geometry/all attachment identities, compare the complete8GB against
source plus exact patches, and require both full result and unchanged-range hashes.
Rehash retained source afterward. Freeze the derivative read-only. Source image
is never opened writable. The current helper deliberately has NO image writer;
any future creation/verification invocation must itself be concretely reviewed.

Resources: writable boot3221225472 + read-only evidence8000000000 + seed<=1MiB;
2 CPUs/3GiB, zero NIC/socket/share. Logical attachment sum deliberately exceeds8GB
as in the reviewed rescue, with only3.22GB writable. New physical/headroom delta
cap512MiB, immediate pre/post-preparation and launch free>=5.5GiB, fresh launch
baseline and one-second conservative hostwide cap; stop at max(baseline-512MiB,
2.5GiB), protecting2GiB reserve. APFS cloning does not justify assuming reclaim or
zero physical growth. No cleanup. Existing runner240s/collector120s/commands10s/
256KiB output remain. Any capacity refusal stops preparation; no retry loop.

## Actual root-device observation proposal (requires reviewed seed amendment)

The frozen rescue seed does not currently print/verify the running root device.
Keep it retained; do not silently call its markers root-device proof. Propose an
additive, fail-closed collector check before any evidence mount, followed by a new
hash-reviewed seed (not prepared in this round):
- bounded `findmnt -n -r -o MAJ:MIN,SOURCE,FSTYPE,OPTIONS /`;
- require its major:minor equal `/dev/vda1` from bounded `lsblk -dn -o MAJ:MIN`;
- require actual `/dev/vda1` PARTUUID equal original `d35a5af0-...-73615f73fc09`,
  using bounded `blkid -s PARTUUID -o value`; record full exact value;
- require `/dev/vdc1` PARTUUID equal proposed `c2fb6dc1-...-017c4cfd3483`;
- retain existing whole/partition blockgetro=1, size8000000000,
  `ro,noload,nodev,nosuid,noexec` actual mount verification, no target execution.
Only public device/UUID/mount metadata is emitted. No filesystem replay, private
file content, installation or repair. If root requires the seed byte-identical,
actual root-device observation remains unavailable: do not waive that gate.
