#!/bin/bash
# Thin authenticated loader only. The pinned Go executable owns all installation,
# credential access, native validation, CA adoption and transactional publication.
set -euo pipefail
set +x
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
unset BASH_ENV ENV CDPATH
fail() { printf '%s\n' 'cloud-8021x: protected artifact staging refused' >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail
# No credential, response body or authorization header is logged.
metadata() { curl --fail --silent --show-error --noproxy '*' --connect-timeout 5 --max-time 15 -H 'Metadata-Flavor: Google' "http://169.254.169.254/computeMetadata/v1/$1"; }
[ "$(metadata project/numeric-project-id)" = '${project_number}' ] || fail
[ "$(metadata instance/name)" = '${instance_name}' ] || fail
# Reject links and writable ancestors before creating anything beneath them.
protect_dir() {
  [ ! -L "$1" ] && [ -d "$1" ] || fail
  [ "$(stat -c %u "$1")" = 0 ] || fail
  mode=$(stat -c %a "$1")
  (( (8#$mode & 0022) == 0 )) || fail
}
for dir in / /var /var/cache; do protect_dir "$dir"; done
if [ ! -e /var/cache/cloud-8021x ]; then mkdir -m 0700 /var/cache/cloud-8021x; fi
protect_dir /var/cache/cloud-8021x
# This root-private lineage prevents another UID from replacing the lock/stage.
[ "$(stat -c %a /var/cache/cloud-8021x)" = 700 ] || fail
lock=/var/cache/cloud-8021x/loader.lock
[ ! -L "$lock" ] || fail
if [ -e "$lock" ]; then
  [ -f "$lock" ] && [ "$(stat -c %u:%a:%h "$lock")" = 0:600:1 ] || fail
fi
exec 9>"$lock"
flock -n 9 || exit 0
stage=$(mktemp -d /var/cache/cloud-8021x/.incoming.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
# Bound both individual artifacts and the complete deployment closure.
total=0
fetch() {
  name=$1 digest=$2 url=$3
  [[ "$name" =~ ^(cloud-8021x|config.yaml|manifest.json|postgres-ca.pem|provenance.json|[a-z0-9][a-z0-9+.-]*_[0-9A-Za-z.+:~-]+_(amd64|arm64|all)[.]deb)$ ]] || fail
  [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || fail
  [[ "$url" =~ ^https://storage.googleapis.com/[a-z0-9.-]+/sha256/[a-f0-9]{64}/[^/?]+\?generation=[0-9]+$ ]] || fail
  [ ! -e "$stage/$name" ] || fail
  # Token stays in a root-only curl header file, never process arguments/output.
  token=$(metadata instance/service-accounts/default/token | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"\]*\)".*/\1/p')
  [[ "$token" =~ ^[A-Za-z0-9._~-]+$ ]] || fail
  printf 'Authorization: Bearer %s\n' "$token" > "$stage/.authorization"
  unset token
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 900 --max-filesize 1073741824 --header "@$stage/.authorization" --output "$stage/$name" "$url"
  rm -f "$stage/.authorization"
  size=$(stat -c %s "$stage/$name")
  total=$((total + size))
  (( size > 0 && size <= 1073741824 && total <= 12884901888 )) || fail
  printf '%s  %s\n' "$digest" "$stage/$name" | sha256sum --status --check || fail
  chown 0:0 "$stage/$name"
  chmod 0600 "$stage/$name"
}
%{ for artifact in artifacts ~}
fetch '${artifact.name}' '${artifact.sha256}' '${artifact.url}'
%{ endfor ~}
for name in cloud-8021x config.yaml manifest.json postgres-ca.pem provenance.json; do
  [ -f "$stage/$name" ] || fail
done
chmod 0700 "$stage/cloud-8021x"
"$stage/cloud-8021x" config validate --config "$stage/config.yaml"
# Never modify live application/CA/config files here. Retain old incoming bytes;
# Go's protected snapshots separately preserve exact installed rollback evidence.
incoming=/var/cache/cloud-8021x/artifacts
if [ -e "$incoming" ] || [ -L "$incoming" ]; then
  protect_dir "$incoming"
  [ "$(stat -c %a "$incoming")" = 700 ] || fail
  previous=$(mktemp -d /var/cache/cloud-8021x/.previous.XXXXXXXX)
  rmdir "$previous"
  mv -T "$incoming" "$previous"
fi
mv -T "$stage" "$incoming"
trap - EXIT
%{ if parallel ~}
exec "$incoming/cloud-8021x" bootstrap prepare --incoming
%{ else ~}
exec "$incoming/cloud-8021x" bootstrap --incoming
%{ endif ~}
