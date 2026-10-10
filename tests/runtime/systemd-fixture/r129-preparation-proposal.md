# R129: preparation code only; creation and launch remain held

The additive collector guard runs before even the evidence block checks/mount.
Actual findmnt root MAJ:MIN/SOURCE/FSTYPE/OPTIONS must identify ext4 `/dev/vda1`;
actual lsblk vda1 MAJ:MIN must match. Bounded blkid must report original root
PARTUUID `d35a5af0-fb25-480f-ab0d-73615f73fc09` and evidencevdc1 PARTUUID
`c2fb6dc1-ec0e-496c-9172-017c4cfd3483`. Each command gets10s plus1s kill grace,
<=1024 output bytes, exactly one terminated line, strict field parsing and a
success-only public metadata frame. Unknown/malformed/multiline/nonzero/timeout
fails before target access. Existing readOnly/ro,noload/nodev/nosuid/noexec and
120s/256KiB collector,135s unit,240s outer limits are unchanged.

`gpt-verify` is read-only. It requires independent plan SHA256 and source/boot/
derivative SHA256+exact sizes, bounded owned canonical regular inputs, distinct
inodes including the plan, strict bounded JSON, exact GUID/CRC fields, fresh boot
identity, full streams and unchanged-range hash. Its JSON receipt reports verified
pins/sizes/fields. It has no write-to-image mode. Working stream buffers remain1MiB.

## Proposed next preparation invocation — NOT executed or authorized yet

All paths below are under owned root
`/private/tmp/cloud8021x-task11-debian-20261001.d5B0lJ` (`R`). New exclusive directory:
`R/readonly-rescue-guid-r129`; abort if it exists. No prior booted clone is reused.
Frozen plan is `R/gpt-r127-plan.json`, SHA256
`40bfa350af0613e600802a90fdc7d39bceb77510f4739b273dd0b9fce3207e85`.

Before creation, the one-second owned capacity supervisor takes a fresh baseline,
requires >=5.5GiB free and enforces max(baseline-512MiB,2.5GiB), protecting2GiB.
Only owned operation children may be stopped; stop/no retry if any gate fails.
No sumdu/shared-extent claim and no cleanup. Recheck immediately after every stage.
The supervisor must cover preparation as well as any later separately approved run.

After all original/full hash pins match, proposed APFS-only clone commands are:

```sh
/bin/cp -c "$R/extracted/disk.raw" "$R/readonly-rescue-guid-r129/boot.img"
/bin/cp -c "$R/fresh-pristine-history-20261009/disk.img" "$R/readonly-rescue-guid-r129/evidence.img"
/bin/cp -c "$R/tart/vms/cloud8021x-task11-owned/nvram.bin" "$R/readonly-rescue-guid-r129/nvram.bin"
```

EFI template remains131072bytes, SHA256
`d31feb5c63cb37d858eb2fb9551bd37cbf3ff48d49c4701cd8f12eb1cdd6c96b`.
Fresh child directory must be created0700 with exclusive mkdir. Verify canonical
owned parents, source O_RDONLY|O_NOFOLLOW, destination O_RDWR|O_NOFOLLOW (relative
to an O_DIRECTORY|O_NOFOLLOW child-dir FD), regular files, UID, exact lengths and
pairwise distinct device/inode across master/source/clones/EFI/seed. Source/clone
full hashes must match their reviewed before pins before any image write. No
sparse expansion, truncation, generic GPT tool, UUID filesystem change or GRUB edit.

The subsequent reviewed inline Python writer must accept NO arbitrary offsets or
paths: fixed plan hash above, fixed new directory, fixed source/boot hashes, fixed
10field list below. For each field only, compare `os.pread(source,n,offset)` and
`os.pread(candidate,n,offset)` against plan Before; require equal fixed Before/After
lengths; perform exactly `os.pwrite(candidate, After, offset)` and require full
length. Across all fields total writes112bytes. Fsync candidate; fchmod0444 and
close its writable descriptor. The writer's only write-image FD is the new owned
candidate; original/source/boot files are read-only. No image writer is currently
implemented or invoked; this exact operation must be reviewed before creation.

Fixed offset:length fields:
`528:4,568:16,600:4,1040:16,2832:16,7999983120:16,7999984912:16,7999999504:4,7999999544:16,7999999576:4`.

Exact proposed write invocation, still NOT executed (the surrounding supervisor
and clone/hash/identity gates above are mandatory). The isolated invocation ignores
inherited Python settings. Every gate uses an explicit checked failure and stays
active even if copied under -O/-OO; the write occurs before its length check:

```sh
python3 -I - <<'PYWRITE'
import os, stat, json, hashlib, base64
from pathlib import Path
def require(condition, message):
 if not condition:
  raise RuntimeError(message)
r = Path('/private/tmp/cloud8021x-task11-debian-20261001.d5B0lJ')
d = r / 'readonly-rescue-guid-r129'
require(r.resolve() == r and d.resolve() == d, 'canonical owned paths')
require(stat.S_IMODE(d.stat().st_mode) == 0o700 and d.stat().st_uid == os.getuid(), 'private owned destination directory')
require((r / 'gpt-r127-plan.json').stat().st_size <= 65536, 'bounded plan length')
plan_bytes = (r / 'gpt-r127-plan.json').read_bytes()
require(hashlib.sha256(plan_bytes).hexdigest() == '40bfa350af0613e600802a90fdc7d39bceb77510f4739b273dd0b9fce3207e85', 'approved plan hash')
p = json.loads(plan_bytes)
fixed = [(528,4),(568,16),(600,4),(1040,16),(2832,16),(7999983120,16),(7999984912,16),(7999999504,4),(7999999544,16),(7999999576,4)]
patches = [(x['offset'],base64.b64decode(x['before'],validate=True),base64.b64decode(x['after'],validate=True)) for x in p['patches']]
require([(o,len(a)) for o,a,b in patches] == fixed, 'exact field offsets and widths')
require(all(len(a) == len(b) for o,a,b in patches) and sum(len(b) for o,a,b in patches) == 112, 'exact112-byte write bound')
source = r / 'fresh-pristine-history-20261009/disk.img'
require(source.resolve() == source, 'canonical immutable source')
parent = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
src = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
dst = os.open('evidence.img', os.O_RDWR | os.O_NOFOLLOW, dir_fd=parent)
def identity(fd):
 st = os.fstat(fd)
 require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_size == 8000000000, 'owned regular8GB image')
 return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
def digest(fd):
 h = hashlib.sha256()
 for offset in range(0,8000000000,1048576):
  n = min(1048576,8000000000-offset)
  b = os.pread(fd,n,offset)
  require(len(b) == n, 'complete bounded read')
  h.update(b)
 return h.hexdigest()
try:
 before = identity(src)
 require(before[:2] != identity(dst)[:2] and os.fstat(dst).st_nlink == 1, 'distinct source/candidate inodes and candidate single link')
 seen = {before[:2],identity(dst)[:2]}
 for path in [r/'extracted/disk.raw',d/'boot.img',d/'nvram.bin']:
  require(path.resolve() == path and path.is_file() and path.stat().st_uid == os.getuid(), 'owned canonical other inputs')
  st = path.stat()
  require((st.st_dev,st.st_ino) not in seen, 'distinct input identities')
  seen.add((st.st_dev,st.st_ino))
 expected = 'e35f2e3cf5bf4ab127e2f0bb2ce8d71f52e82bceb4e80680de7175e1cc366845'
 require(digest(src) == digest(dst) == expected, 'exact source/candidate before hashes')
 for off,a,b in patches:
  require(os.pread(src,len(a),off) == os.pread(dst,len(a),off) == a, 'exact field before bytes')
 for off,a,b in patches:
  written = os.pwrite(dst,b,off)
  require(written == len(b), 'complete GPT field write')
 os.fsync(dst)
 require(digest(dst) == 'd47f5e7283cde3f2e7eee5938986e24c093f918f2eb4035de5677134825beb4b', 'exact derivative result hash')
 require(digest(src) == expected and identity(src) == before, 'source hash and inode/size/timestamps unchanged')
 os.fchmod(dst,0o444)
finally:
 os.close(dst); os.close(src); os.close(parent)
PYWRITE
```

Then invoke the frozen new helper read-only, with literal independent pins:

```sh
"$R/systemd-fixture-gpt-r129" gpt-verify \
 --source "$R/fresh-pristine-history-20261009/disk.img" \
 --source-size 8000000000 \
 --source-sha256 e35f2e3cf5bf4ab127e2f0bb2ce8d71f52e82bceb4e80680de7175e1cc366845 \
 --boot "$R/readonly-rescue-guid-r129/boot.img" \
 --boot-size 3221225472 \
 --boot-sha256 02c4d0d6812fe927e15daf323852b216efd514c0d00fb497ca84193d694c9d96 \
 --derivative "$R/readonly-rescue-guid-r129/evidence.img" \
 --derivative-size 8000000000 \
 --derivative-sha256 d47f5e7283cde3f2e7eee5938986e24c093f918f2eb4035de5677134825beb4b \
 --plan "$R/gpt-r127-plan.json" \
 --plan-sha256 40bfa350af0613e600802a90fdc7d39bceb77510f4739b273dd0b9fce3207e85
```

Require unchanged-range SHA256
`2d33780e7199e0688a37d7fb3190ec58462d93ffb1a084ed9b1c04276193b622`.
After verification, independently rehash retained R105/master/EFI-template and
compare pre/post source inode,size,mtime,ctime. Preserve full receipt and refusal
on any mismatch; do not launch. Freeze root/derivative/seed identity inventory.

New seed preparation also remains held. It would copy the retained seed's exact
NoCloud metadata/network/user-data, replace only rescue.sh + checks.sum, create a
new short-name ISO<=1MiB and hash/review it. Old seed ISO/collector and every failure
remain untouched. New seed hash cannot be claimed before approved creation.

Any later approved run retains2CPU/3GiB/zeroNIC/socket/share and fresh admission:
3.22GB writable boot,8GB explicitly read-only derivative,read-only seed,ownEFI;
combined logical size is deliberately >8GB, as in prior rescue approval. It must
observe the actual root device and read-only evidence before collection. No target
execution, replay, fsck, package/347-state changes, installation or product actions.
This remains a diagnostic proposal, not proof of R116 selected root or dpkg cause.
