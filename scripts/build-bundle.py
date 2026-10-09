#!/usr/bin/env python3
"""Development/release producer for authenticated, finite Debian13 bundles."""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCTS = dict.fromkeys(['freeradius', 'freeradius-common', 'freeradius-config', 'freeradius-utils',
                         'freeradius-rest', 'freeradius-postgresql', 'libfreeradius3'], '3.2.10+dfsg-2+trixie.campus4')
PRODUCTS.update({'step-ca': '0.30.2-1+campus1', 'datadog-agent': '1:7.84.2-1+campus1',
                 'datadog-agent-ddot': '1:7.84.2-1+campus1'})


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def verified_inputs(directory):
    directory = pathlib.Path(directory)
    checksum_file = directory / 'SHA256SUMS'
    if directory.is_symlink() or not directory.is_dir() or checksum_file.is_symlink() or not checksum_file.is_file():
        raise ValueError('mandatory regular input/checksum manifest unavailable')
    if checksum_file.stat().st_size > 1 << 20:
        raise ValueError('oversized checksum manifest')
    entries = {}
    for line in checksum_file.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.:+~/-]+)', line)
        if not match:
            raise ValueError('invalid checksum entry')
        checksum, relative = match.groups()
        path = pathlib.PurePosixPath(relative)
        if path.is_absolute() or any(part in ['', '.', '..'] for part in relative.split('/')) or relative in entries or relative == 'SHA256SUMS':
            raise ValueError('unsafe or duplicate checksum entry')
        entries[relative] = checksum
    paths = list(directory.rglob('*'))
    if not entries or len(entries) > 4096 or any(path.is_symlink() for path in paths):
        raise ValueError('unbounded or linked release inputs')
    files = {path.relative_to(directory).as_posix() for path in paths if path.is_file() and path != checksum_file}
    if files != entries.keys():
        raise ValueError('every release input must be checksummed exactly once')
    for relative, checksum in entries.items():
        if digest(directory / relative) != checksum:
            raise ValueError('release input checksum mismatch: ' + relative)
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('architecture', choices=['amd64', 'arm64'])
    parser.add_argument('output', type=pathlib.Path)
    for name in ['native', 'monitoring', 'step-ca', 'dependencies']:
        parser.add_argument('--' + name, type=pathlib.Path, required=True)
    args = parser.parse_args()
    assert args.output.is_dir() and not any(args.output.iterdir()), 'output must be empty'
    dependencies = (ROOT / 'patches/freeradius/trixie-dependencies.txt').read_text().splitlines()
    expected = set(PRODUCTS) | set(dependencies)
    assert len(expected) == 62
    entries = {}
    for family, directory in [('native', args.native), ('monitoring', args.monitoring),
                              ('step-ca', args.step_ca), ('dependencies', args.dependencies)]:
        for relative, checksum in verified_inputs(directory).items():
            path = directory / relative
            if path.suffix != '.deb':
                target = args.output / 'provenance' / family / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                continue
            fields = subprocess.check_output(['dpkg-deb', '-f', str(path), 'Package', 'Version', 'Architecture'], text=True)
            meta = dict(line.split(': ', 1) for line in fields.splitlines())
            name, version, arch = [meta[key] for key in ['Package', 'Version', 'Architecture']]
            # step-ca's producer builds both architectures in a single run.
            if family == 'step-ca' and arch != args.architecture:
                continue
            assert name in expected and name not in entries and arch in [args.architecture, 'all'], meta
            assert name not in PRODUCTS or version == PRODUCTS[name], meta
            assert name == 'freeradius-common' or name in dependencies or arch == args.architecture, meta
            assert path.name == f'{name}_{version}_{arch}.deb', path.name
            assert 0 < path.stat().st_size <= 1 << 30
            entries[name] = dict(name=name, version=version, architecture=arch, sha256=checksum)
            shutil.copyfile(path, args.output / path.name)
    assert set(entries) == expected, ('incomplete or unexpected package closure', expected - entries.keys())
    assert sum(path.stat().st_size for path in args.output.glob('*.deb')) <= 12 << 30
    with tempfile.TemporaryDirectory(prefix='cloud8021x-bundle-collector-') as temp:
        package = args.output / f'datadog-agent-ddot_{PRODUCTS["datadog-agent-ddot"]}_{args.architecture}.deb'
        subprocess.run(['dpkg-deb', '-x', str(package), temp], check=True)
        collector = pathlib.Path(temp) / 'opt/datadog-agent/embedded/bin/otel-agent'
        collector_hash = digest(collector)
    manifest = dict(schema=1, architecture=args.architecture, collector_sha256=collector_hash,
                    artifacts=[entries[name] for name in sorted(entries)])
    (args.output / 'package-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    paths = sorted(path for path in args.output.rglob('*') if path.is_file())
    (args.output / 'SHA256SUMS').write_text(''.join(f'{digest(path)}  {path.relative_to(args.output).as_posix()}\n' for path in paths))
    print(json.dumps(dict(architecture=args.architecture, archives=len(entries),
                         package_manifest_sha256=digest(args.output / 'package-manifest.json'))))


if __name__ == '__main__':
    main()
