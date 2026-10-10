# Proposed fresh nested-only stage after the R99 correction

Preparation is complete after conditional root authorization; the fresh VM has
never booted. Launch still requires root review of the amended copy diff and
helper/seed hashes plus a new bounded run grant. Retain the interrupted `nested-disk.img`, its EFI/seed, and all
v4/v5/R99 logs unchanged. Do not reuse or widen their recovery exceptions.

1. Rechecked original raw SHA512 is
   `bfaff28606ee833aef5b42cc057105cf0c6d59137d0198492ecd46ec5afc36c998860d020207f71752343230a552dc81c73b27d583bacb11ad961bc452eed992`.
   After approval, make a uniquely named APFS clone (`cp -c`) of only this
   `extracted/disk.raw`, then sparsely extend the new file to8,000,000,000bytes.
   Copy the already-owned original outer EFI to a new path. Never copy the
   interrupted root, its package database or its fixture state. Initial raw
   logical size3,221,225,472bytes; active VM logical disk remains under8GiB.
2. Use a new short-name read-only NoCloud seed and instance ID. Build/hash the
   corrected Linux development helper. Seed contains `fixture`/`fixture.sum`,
   the pinned original baseline as `base.txt`, exact26 lock as `dev.txt`, and
   all26 `p000.deb`…`p025.deb` archives. Recheck sizes/hashes and seed size below
   512MiB. Prior seeds remain untouched. Expected seed remains about76MiB.
3. Same owned output-only VZ runner,2CPU/3GiB/zero NIC/socket/share, at most one
   newly approved600s attempt. No host listeners, trust/settings changes,
   package acquisition or production activation. Fresh disk has no saved
   interrupted-install evidence; its initial authoritative dpkg-query view
   must match all321 clean baseline identities with no extras. No dated v4
   recovery exception is needed or enlarged. Any dirty/unexpected state stops.
4. Install only exact26 offline, with package service starts blocked. Re-query
   authoritative merged dpkg state independently after installation. All321+26
   identities must be fully installed, with no pending/awaited fields and an
   empty fresh dpkg audit before any bridge or nspawn command. Do not accept
   man-db pending state, even on the fresh disk, as a successful final gate.
5. Only after those gates, run the existing one-node private bridge/overlay/
   systemd PID1/cgroup/owned16MiB loop/reboot-persistence canary. Preserve the
   guest free-space checks (at least3GiB before lower-root copy and1GiB after).
   Full application/CA/collector activation remains prohibited. Exit/failure
   markers and the actual log determine the result, not launcher exit zero.

## Measured physical budget and prepared artifacts

Read-only GPT/ext4 counters (no mount/launch) show original base used947,744,768
bytes and accepted clean outer used1,045,823,488/free6,819,938,304bytes; both have
journal-recovery=false. Exact26 installed-size sum328,251,392bytes. The failed
retained disk has journal-recovery=true and is not a completed-install bound.
No previous full26/lower-copy acceptance exists. Evidence is retained in
`owned-footprint-measurement.json` under the owned artifact directory.

The existing exclusions already omit `/run` read-only seed mounts and all
`/var/lib/cloud8021x-task11` state; no seed archives are being copied into lower.
No OS files are pruned. The amended script keeps all exclusions and assertions,
measures source with matching exclusions, refuses more than1.5GiB, uses sparse
GNU tar with a1.625GiB bounded archive stream, and refuses a resulting lower over
1.75GiB. Existing guest-free checks remain3GiB before copy and1GiB afterward.
A tiny cached networkless test preserved a3GiB sparse file at4096bytes allocated
with exact content; shell syntax passed.

Fresh incremental allowance is3.5GiB:1GiB clone/boot/dependency writes,1.75GiB
bounded lower copy,0.75GiB seed/metadata/transient margin. Retain a2GiB host-free
reserve and recheck immediately before launch/during the run. APFS clone extent
sharing is not counted as duplicated physical allocation. No unrelated cleanup
or increased8GB logical disk is permitted.

All input hashes matched before preparation. New owned directory:
`/private/tmp/cloud8021x-task11-debian-20261001.d5B0lJ/fresh-nested-reviewed/`.
Its `disk.img` is a new APFS clone of the original raw, expanded sparsely to
8,000,000,000bytes; the original3GiB prefix was hashed again on the clone and
matches the verified raw SHA512. Own copied EFI is `nvram.bin`. Prior disks,
logs, images and seeds remain untouched.

- Helper `fixture-authoritative-fresh` SHA256: `f4f469b2e3004b72437a77ce6f35c2fc5cd9826e40865f2fbe24a018a0333929`.
- Read-only `seed.iso`,76,171,264bytes, SHA256: `6309543de2be14279c5e6b183dc1796fcf04435b779dcb79459e447012fd5345`.
- Copy amendment `sparse-copy-capacity.patch` SHA256: `b18bf96ca3b17be4ebdacbe665b5950a270e9315d6d21e61a6d18cbbf04ecdcb`.

Host free was6,027,608,064bytes before preparation (above5.5GiB condition).
Latest post-preparation sample was8,314,880,000bytes; no owned or unrelated
artifacts were deleted by this agent. `preparation.json` records all hashes,
logical size and capacity samples. Every budget gate must be rechecked at the
actual launch; these are measurements, not a reservation or success claim.
