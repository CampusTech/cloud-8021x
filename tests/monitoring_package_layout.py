"""Development-only acceptance gate for the minimal matched Agent/DDOT packages.

Run on Linux with dpkg-deb and Go available. Checks every actual ELF file in the
archive, not a handpicked list of executable paths. Binary vulnerability scans
are mandatory separately in the build recipe.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile

VERSION = '1:7.84.2-1+campus1'
EXPECTED = {
    'datadog-agent': 'opt/datadog-agent/bin/agent/agent',
    'datadog-agent-ddot': 'opt/datadog-agent/embedded/bin/otel-agent',
}


def check(archive, name, architecture):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        subprocess.run(['dpkg-deb', '-x', str(archive), str(root / 'files')], check=True)
        subprocess.run(['dpkg-deb', '-e', str(archive), str(root / 'control')], check=True)
        for action in ['preinst', 'postinst', 'prerm', 'postrm', 'triggers']:
            assert not (root / 'control' / action).exists(), f'package activates host behavior: {action}'
        metadata = subprocess.check_output(['dpkg-deb', '-f', str(archive), 'Package', 'Version', 'Architecture'], text=True)
        assert metadata == f'Package: {name}\nVersion: {VERSION}\nArchitecture: {architecture}\n', metadata
        binaries = []
        for path in sorted((root / 'files').rglob('*')):
            if path.is_symlink() or not path.is_file():
                continue
            with path.open('rb') as stream:
                if stream.read(4) != b'\x7fELF':
                    continue
            result = subprocess.run(['go', 'version', '-m', str(path)], capture_output=True, text=True)
            if result.returncode == 0 and ': go1.' in result.stdout:
                relative = str(path.relative_to(root / 'files'))
                binaries.append(relative)
                assert ': go1.27.2\n' in result.stdout, (relative, result.stdout.splitlines()[0])
                assert '\tbuild\tGOARCH=' + architecture in result.stdout, relative
        assert binaries == [EXPECTED[name]], ('unexpected or missing Go executables', binaries)
        for path in (root / 'files').rglob('*'):
            relative = str(path.relative_to(root / 'files'))
            assert '/systemd/' not in relative and not relative.startswith('etc/init.d/'), relative
        executable = root / 'files' / EXPECTED[name]
        assert executable.stat().st_mode & 0o111, 'binary is not executable'
        if name == 'datadog-agent':
            for check_name in ['cpu', 'disk', 'io', 'load', 'memory', 'network', 'uptime']:
                assert (root / 'files' / f'etc/datadog-agent/conf.d/{check_name}.d/conf.yaml.default').is_file(), check_name
            assert (root / 'files' / 'opt/datadog-agent/embedded/lib/libdatadog-agent-rtloader.so').exists()
        print(f'PASS {name} {architecture}: exact fixed executable inventory and inert package')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', choices=EXPECTED)
    parser.add_argument('architecture', choices=['amd64', 'arm64'])
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    check(args.archive, args.package, args.architecture)
