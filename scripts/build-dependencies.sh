#!/usr/bin/env bash
# Acquire the static reviewed runtime closure from the pinned build snapshot.
# This is a CI producer, never an on-node resolver or install command.
set -euo pipefail
# Package modes must not depend on the invoking shell or builder account.
umask 022
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
arch=${1:?usage: build-dependencies.sh amd64_or_arm64 EMPTY_OUTPUT_DIRECTORY}
output=${2:?empty output required}
[[ -f /.dockerenv && "${C8021X_DISPOSABLE_BUILD:-}" == 1 && -f /build-evidence/trixie.Release ]] || exit 2
[[ "$arch" == amd64 || "$arch" == arm64 ]] || exit 2
[[ "$(dpkg --print-architecture)" == "$arch" ]] || exit 2
[[ -d "$output" && -z "$(ls -A -- "$output")" ]] || exit 2
output=$(cd -- "$output" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mapfile -t names < "$root/patches/freeradius/trixie-dependencies.txt"
[[ ${#names[@]} == 52 ]]
specs=()
for name in "${names[@]}"; do
  version=$(LC_ALL=C apt-cache policy "$name" | awk '/Candidate:/ {print $2}')
  [[ -n "$version" && "$version" != '(none)' ]]
  specs+=("$name=$version")
done
cd "$work"
apt-get download "${specs[@]}"
python3 - "$arch" "$output" "$root" <<'PY'
import hashlib,json,pathlib,re,shutil,subprocess,sys
arch,output,root=sys.argv[1:]
out=pathlib.Path(output)
allow=(pathlib.Path(root)/'patches/freeradius/trixie-dependencies.txt').read_text().splitlines()
# Keep the build producer and protected consumer allowlists exactly equal.
go=(pathlib.Path(root)/'internal/privileged/host/dependencies.go').read_text().split('var dependencyArtifacts = []string{',1)[1].split('}',1)[0]
assert allow==re.findall(r'"([a-z0-9+.-]+)"',go)
fixed={'libct4':'1.3.17+ds-2+deb13u1','freetds-common':'1.3.17+ds-2+deb13u1','libsqlite3-0':'3.46.1-7+deb13u2','perl':'5.40.1-6+deb13u1'}
seen=set(); entries=[]
for path in sorted(pathlib.Path('.').glob('*.deb')):
    fields=subprocess.check_output(['dpkg-deb','-f',str(path),'Package','Version','Architecture'],text=True)
    meta=dict(line.split(': ',1) for line in fields.splitlines())
    name,version,package_arch=[meta[k] for k in ['Package','Version','Architecture']]
    assert name in allow and name not in seen and package_arch in [arch,'all'],meta
    assert name not in fixed or version==fixed[name],meta
    digest=hashlib.sha256(path.read_bytes()).hexdigest()
    indexed=subprocess.check_output(['apt-cache','show',name+'='+version],text=True)
    matches=[]
    for block in indexed.split('\n\n'):
        entry=dict(line.split(': ',1) for line in block.splitlines() if ': ' in line and not line.startswith(' '))
        if entry.get('Architecture')==package_arch and entry.get('SHA256')==digest and entry.get('Size')==str(path.stat().st_size):
            matches.append(entry)
    assert matches,(name,'archive does not match the signed snapshot index')
    filename=f'{name}_{version}_{package_arch}.deb'
    shutil.copyfile(path,out/filename)
    entries.append(dict(name=name,version=version,architecture=package_arch,sha256=digest,source=matches[0]['Filename']))
    seen.add(name)
assert seen==set(allow)
(out/'dependency-provenance.json').write_text(json.dumps(entries,indent=2)+'\n')
PY
cp "$root/patches/freeradius/trixie-dependencies.txt" "$output/"
cd "$output"
sha256sum -- * > SHA256SUMS
