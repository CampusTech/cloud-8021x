"""Inventory and scan every Go ELF executable in an assembled release closure."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import tarfile

EXPECTED = {
    'datadog-agent': 'opt/datadog-agent/bin/agent/agent',
    'datadog-agent-ddot': 'opt/datadog-agent/embedded/bin/otel-agent',
    'step-ca': 'usr/bin/step-ca',
}


def verify_executable_modes(archive, relative):
    expected = {relative, *(str(path) for path in Path(relative).parents if str(path) != '.')}
    seen = set()
    rejected = []
    with subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(archive)], stdout=subprocess.PIPE) as process:
        with tarfile.open(fileobj=process.stdout, mode='r|') as contents:
            for member in contents:
                name = str(Path(member.name))
                if name in expected:
                    if member.uid != 0 or member.gid != 0:
                        rejected.append((name, 'executable hierarchy is not root owned'))
                    if not member.mode & 0o111 or member.mode & 0o022:
                        rejected.append((name, 'executable hierarchy permits unprivileged writes'))
                    if not (member.isfile() if name == relative else member.isdir()):
                        rejected.append((name, 'unexpected executable hierarchy file type'))
                    seen.add(name)
        assert process.wait() == 0
    assert not rejected, rejected
    assert seen == expected, ('incomplete executable hierarchy', expected - seen)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--scanner', required=True)
    args = parser.parse_args()
    scanner = subprocess.check_output([args.scanner, '-version'], text=True)
    assert 'Scanner: govulncheck@v1.8.0' in scanner
    args.evidence.mkdir(parents=True, exist_ok=True)
    (args.evidence / 'scanner-version.txt').write_text(scanner)
    manifest = json.loads((args.bundle / 'package-manifest.json').read_text())
    found = {}
    for entry in manifest['artifacts']:
        archive = args.bundle / f'{entry["name"]}_{entry["version"]}_{entry["architecture"]}.deb'
        with archive.open('rb') as source:
            assert hashlib.file_digest(source, 'sha256').hexdigest() == entry['sha256'], archive.name
        with tempfile.TemporaryDirectory(prefix='cloud8021x-elf-inventory-') as temp:
            subprocess.run(['dpkg-deb', '-x', str(archive), temp], check=True)
            for path in sorted(Path(temp).rglob('*')):
                if path.is_symlink() or not path.is_file():
                    continue
                with path.open('rb') as stream:
                    if stream.read(4) != b'\x7fELF':
                        continue
                info = subprocess.run(['go', 'version', '-m', str(path)], capture_output=True, text=True)
                if info.returncode != 0 or ': go1.' not in info.stdout:
                    continue
                relative = path.relative_to(temp).as_posix()
                name = entry['name']
                assert name not in found and EXPECTED.get(name) == relative, (name, relative)
                assert ': go1.27.2\n' in info.stdout and '\tbuild\tGOARCH=' + manifest['architecture'] in info.stdout
                verify_executable_modes(archive, relative)
                found[name] = relative
                (args.evidence / (name + '-buildinfo.txt')).write_text(info.stdout)
                result = subprocess.run([args.scanner, '-mode=binary', str(path)], capture_output=True, text=True)
                (args.evidence / (name + '-security.txt')).write_text(result.stdout + result.stderr)
                assert result.returncode == 0, (name, 'actual binary security scan failed')
    assert found == EXPECTED, found
    (args.evidence / 'go-executables.json').write_text(json.dumps(found, indent=2) + '\n')
    print('PASS: every retained Go executable inventoried and scanned:', json.dumps(found))


if __name__ == '__main__':
    main()
