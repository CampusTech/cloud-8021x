# R105 timeout diagnosis — read-only rescue proposal

Status: proposal only; no launcher/source repair, new image, seed or VM has been
created. Root must approve the exact next diagnostic before execution. This is
not an install retry or a route to bypass the final prerequisite gate.

## Facts already established

- R105's actual host watchdog fired at 600 seconds, exit 2. The last installer
  line is `Unpacking perl-modules-5.40 (5.40.1-6+deb13u1)`. No `Setting up` lines,
  final347/audit marker, EXIT trap result, lower copy or nested start appears.
- The frozen script redirects stdout/stderr to `/dev/hvc0`; systemd provides its
  other default I/O. It synchronously runs `dpkg --install` on the approved26
  archives. The oneshot has `TimeoutStartSec=440`, with no explicit kill settings.
  We have no guest-monotonic timestamp or recorded unit result from this attempt.
- VZ's serial writer is the launcher's stdout, directly attached to the retained
  regular log file. There is no host pipe reader in this path. Total serial log
  is only23,353bytes. The same console also shows getty login/cursor queries.
- Authenticated p018 has1,336 regular files,231 directories,19,587,030 payload
  bytes and only `control`/`md5sums` control members; no maintainer scripts.
  Previously unpacked libllvm19 has123,289,691bytes but only5 regular files;
  libperl5.40 has400 files/31,386,987bytes. Small-file durability/metadata work is
  therefore a candidate, not an established cause. A perl package prompt or
  maintainer-script loop is not supported by the p018 control inventory.
- Host space minimum4,299,808,768bytes at07:17:32UTC rebounded to6,022,967,296bytes
  three seconds later. This is host-wide accounting, not guest block-I/O proof.
  Do not attribute the transient delta to the installer.

## Hypotheses and evidence needed

| Hypothesis | Evidence that would distinguish it |
| --- | --- |
| Installer making slow small-file/storage progress | dpkg log timestamps and committed `updates/`/package-list progress advancing after last serial message; a later live probe would need child CPU ticks, write_bytes, syscall/wchan and block counters. |
| Guest console backpressure or terminal interaction | Package state stops while a live dpkg thread waits in tty/virtio-console write/read with stable I/O; current low-volume regular-file sink alone neither proves nor excludes guest terminal blocking. |
| Unit timeout/termination rather than running installer | Retained unit journal with monotonic start/timeout/kill/result entries; compare elapsed guest time against actual host600s. Absence of EXIT output is insufficient because the script's trap may not execute or reach the serial sink when its group is terminated. |
| Guest timer/scheduling stall | Retained journal monotonic progression diverges from host interval; a later live probe would require simultaneous CLOCK_MONOTONIC/BOOTTIME/REALTIME samples and process state. There are no such measurements yet. |

## One proposed diagnostic: read-only stopped-disk rescue

Use the existing independent-kernel VZ route, existing Swift/codesign tools and
only `com.apple.security.virtualization`. No host mount, network device, socket,
share, listener, setting change or credential. No Docker/Orb kernel dependency.

1. Reverify original raw SHA512 and the retained R105 disk SHA256
   `e35f2e3cf5bf4ab127e2f0bb2ce8d71f52e82bceb4e80680de7175e1cc366845`.
   Preserve original, R105 and every earlier failure byte-for-byte.
2. After approval, create a uniquely owned APFS boot clone of the original
   **3,221,225,472-byte image without enlargement**, own EFI and a small synthetic
   read-only NoCloud diagnostic seed. Hash all inputs and present them before
   launch. New seed contains only the bounded read-only collector described
   below; it never starts the old prerequisite script or runs package changes.
3. A separately reviewed development runner adds exactly one explicit read-only
   VZ block attachment for the retained R105 disk. Writable boot remains3.22GB;
   seed<=1MiB; retained data disk remains8,000,000,000bytes. **This adds a second
   data disk and total attached logical capacity exceeds8GB. That change needs
   explicit root approval; it does not enlarge any existing image or duplicate
   its data.** No write-capable alias to the retained disk is exposed.
4. Same2CPU/3GiB/zeroNIC/socket/share. Use the existing default240-second host
   deadline, a120-second guest collector deadline and poweroff after collection.
   Immediate host free>=5.5GiB,2GiB reserve/2.5GiB early stop; also cap additional
   host allocation conservatively at512MiB from launch. No deadline extension.
5. Guest proves PID1/kernel and only loopback before collection. Require the
   extra whole device read-only (`blockdev --getro`), inspect partition1's ext4
   identity and mount it `ro,noload,nodev,nosuid,noexec`. Check both device and
   mount read-only flags. Do not replay the filesystem journal, fsck, chroot,
   execute target binaries, install/configure packages or recover triggers.
6. Collect only these fixed development evidence paths and counters, each with
   explicit bounds (total emitted bytes<=256KiB; command deadlines<=10seconds):
   - target `/var/log/dpkg.log` tail and metadata; target `/var/lib/dpkg/status`
     SHA/size, `updates/` filenames/sizes/hashes, and **rescue dpkg-query** with
     `--admindir=<readonly-target>/var/lib/dpkg` for effective package/status/
     pending/awaited tuples;
   - target package-info metadata for perl-modules only (list existence/line
     count and any named `.dpkg-new`/temporary evidence), not an OS-wide scan;
   - target persistent journal, if present: boot IDs plus unit messages for
     task11-nested-prep, cloud-final, serial-getty@hvc0 and kernel storage errors,
     preserving monotonic timestamps and journal errors. Do not claim a missing
     persistent journal proves anything about the prior running process;
   - target unit-file bytes/hash and relevant guest filesystem counters.
     No shadow, credentials, source captures or product configuration data.
7. Print a framed compact result to serial, unmount the data device and poweroff.
   Rehash the retained R105 disk afterward; any change invalidates the forensic
   result. Preserve rescue log/disk regardless of outcome; no automatic retry.

The `noload` view intentionally avoids modifying evidence and may lack the most
recent uncommitted ext4 journal data. Effective dpkg-query merges the visible
DPKG update files, but it cannot supply missing filesystem-journal writes. Treat
missing/inconsistent files as crash-state evidence, never as a clean baseline or
permission to resume installation. This probe cannot recover historical live
CPU/wchan data; if records are inconclusive, return that limitation and seek a
separately reviewed instrumented diagnostic rather than infer a repair.

No repair is proposed now. If a harness defect is established, first reproduce
it in a meaningful bounded regression, then change only its confirmed cause.
All package identities, final347/audit requirements and product gates remain
unchanged. Four-node assembly stays blocked on real nested platform acceptance.
