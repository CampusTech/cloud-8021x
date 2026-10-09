"""Mandatory authenticated current bundle inputs for disposable native fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release_bundle', ROOT / 'scripts/build-bundle.py')
BUNDLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUNDLE)


def verify_bundle(directory, architecture=None):
    directory = Path(directory)
    checksums = BUNDLE.verified_inputs(directory)
    manifest_path = directory / 'package-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    arch = manifest['architecture']
    if manifest.get('schema') != 1 or arch not in ['amd64', 'arm64'] or architecture not in [None, arch]:
        raise ValueError('current bundle architecture/schema mismatch')
    dependencies = (ROOT / 'patches/freeradius/trixie-dependencies.txt').read_text().splitlines()
    expected = set(BUNDLE.PRODUCTS) | set(dependencies)
    archives = {}
    for artifact in manifest['artifacts']:
        name, version, package_arch = (artifact[key] for key in ['name', 'version', 'architecture'])
        if name not in expected or name in archives or package_arch not in [arch, 'all']:
            raise ValueError('unexpected or duplicate native bundle identity')
        if name in BUNDLE.PRODUCTS and version != BUNDLE.PRODUCTS[name]:
            raise ValueError('obsolete or unreviewed product package revision')
        filename = f'{name}_{version}_{package_arch}.deb'
        if checksums.get(filename) != artifact['sha256']:
            raise ValueError('manifest/archive checksum binding mismatch')
        archives[name] = filename
    if set(archives) != expected or len(archives) != 62:
        raise ValueError('incomplete current package closure')
    return manifest, archives, hashlib.sha256(manifest_path.read_bytes()).hexdigest()


if __name__ == '__main__':
    manifest, archives, _ = verify_bundle(sys.argv[1], sys.argv[2])
    # The existing bootstrap test supplies synthetic companions to exercise their
    # maintainer suppression and rollback; all native binaries/dependencies are real.
    for name, filename in sorted(archives.items()):
        if name not in ['datadog-agent', 'datadog-agent-ddot', 'step-ca']:
            print('/bundle/' + filename)
