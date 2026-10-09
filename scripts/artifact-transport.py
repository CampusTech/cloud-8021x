#!/usr/bin/env python3
"""CI-only bounded tar transport; preserve literal Debian versions behind safe names."""
import argparse
import hashlib
import importlib.util
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile

SPEC = importlib.util.spec_from_file_location('bundle', Path(__file__).with_name('build-bundle.py'))
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)
MAX_FILES = 4097
MAX_FILE = 1 << 30
MAX_BYTES = 16 << 30


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    return (bool(re.fullmatch(r'[A-Za-z0-9_.:+~/-]+', name)) and not path.is_absolute()
            and all(part not in ['', '.', '..'] for part in name.split('/')))


def pack(source, archive):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+\.tar', archive.name):
        raise ValueError('transport must use a safe .tar basename')
    entries = BUNDLE.verified_inputs(source)
    names = sorted([*entries, 'SHA256SUMS'])
    if len(names) > MAX_FILES or any((source / name).stat().st_size > MAX_FILE for name in names):
        raise ValueError('component exceeds bounded transport')
    if sum((source / name).stat().st_size for name in names) > MAX_BYTES:
        raise ValueError('component exceeds aggregate transport size')
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists() or archive.is_symlink() or Path(str(archive) + '.sha256').exists():
        raise ValueError('transport output must be new')
    with archive.open('xb') as output, tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as contents:
        for name in names:
            info = contents.gettarinfo(str(source / name), arcname=name)
            if not info.isfile():
                raise ValueError('transport contains nonregular file')
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = 1791417600
            info.mode = 0o644
            with (source / name).open('rb') as data:
                contents.addfile(info, data)
    Path(str(archive) + '.sha256').write_text(digest(archive) + '  ' + archive.name + '\n')


def unpack(archive, destination):
    checksum = Path(str(archive) + '.sha256')
    if (archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_BYTES + (MAX_FILES << 14)
            or checksum.is_symlink() or not checksum.is_file() or checksum.stat().st_size > 1024):
        raise ValueError('invalid bounded regular transport')
    if checksum.read_text() != digest(archive) + '  ' + archive.name + '\n':
        raise ValueError('transport checksum mismatch')
    if destination.exists() or destination.is_symlink():
        raise ValueError('destination must be new')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'r:') as contents:
        members = []
        names = set()
        total = 0
        for member in contents:
            if (not safe_name(member.name) or member.name in names or not member.isfile()
                    or member.issparse() or member.size < 0 or member.size > MAX_FILE):
                raise ValueError('unsafe or oversized transport member')
            names.add(member.name)
            total += member.size
            members.append(member)
            if len(members) > MAX_FILES or total > MAX_BYTES:
                raise ValueError('unbounded transport archive')
        with tempfile.TemporaryDirectory(prefix='.artifact-transport-', dir=destination.parent) as temporary:
            stage = Path(temporary) / 'verified'
            stage.mkdir()
            for member in members:
                target = stage / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                with contents.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
                if target.stat().st_size != member.size:
                    raise ValueError('truncated transport member')
                target.chmod(0o644)
            BUNDLE.verified_inputs(stage)
            stage.rename(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['pack', 'unpack'])
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    {'pack': pack, 'unpack': unpack}[args.operation](args.source, args.destination)


if __name__ == '__main__':
    main()
