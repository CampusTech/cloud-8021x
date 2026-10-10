#!/bin/bash
# Development-only forensic collector. Never executes anything from the target.
evidence_root=/mnt/task11-evidence

validate_evidence_mount() {
 local fs options source target extra
 [[ $1 != *$'\n'* ]] || return 1
 read -r fs options source target extra <<< "$1"
 test "$fs" = ext4 && test "$source" = /dev/vdc1 && test "$target" = /mnt/task11-evidence && test -z "$extra" || return 1
 case ",$options," in *,rw,*) return 1;; esac
 local flag
 for flag in ro nosuid nodev noexec; do
  case ",$options," in *,$flag,*) ;; *) return 1;; esac
 done
 case ",$options," in *,noload,*|*,norecovery,*) ;; *) return 1;; esac
}

bounded_probe() {
 local label=$1
 shift
 printf 'PROBE_BEGIN %s\n' "$label"
 (
  set +e
  spool=$(mktemp "${TMPDIR:-/tmp}/cloud8021x-task11-rescue.XXXXXX") || exit 1
  trap 'rm -f "$spool"' EXIT
  timeout --signal=TERM --kill-after=1s 10s "$@" > >(head -c 32769 > "$spool") 2>&1
  status=$?
  wait
  bytes=$(wc -c < "$spool")
  head -c 32768 "$spool"
  truncated=0; test "$bytes" -le 32768 || truncated=1
  printf '\nPROBE_END %s status=%s truncated=%s\n' "$label" "$status" "$truncated"
 )
}

bounded_collection() {
 (
  set +e
  spool=$(mktemp "${TMPDIR:-/tmp}/cloud8021x-task11-rescue-all.XXXXXX") || exit 1
  trap 'rm -f "$spool"' EXIT
  timeout --signal=TERM --kill-after=1s 120s "$@" > >(head -c 262001 > "$spool") 2>&1
  result=$?
  wait
  bytes=$(wc -c < "$spool")
  head -c 262000 "$spool"
  truncated=0; test "$bytes" -le 262000 || { truncated=1; result=125; }
  printf '\nTASK11_RESCUE_EXIT=%s truncated=%s\n' "$result" "$truncated"
  exit "$result"
 )
}

# Reject symlinks in any component and all paths outside the one mounted target.
evidence_file() {
 local relative=$1 candidate resolved
 case "$relative" in var/log/dpkg.log|var/lib/dpkg/status|var/lib/dpkg/updates/[0-9][0-9][0-9][0-9]|var/lib/dpkg/info/perl-modules-5.40.list|var/lib/dpkg/info/perl-modules-5.40.list-new|etc/systemd/system/task11-nested-prep.service) ;; *) return 1;; esac
 candidate="$evidence_root/$relative"
 resolved=$(timeout --kill-after=1s 10s realpath "$candidate") || return 1
 test "$resolved" = "$candidate" && test -f "$candidate" && test ! -L "$candidate" || return 1
 printf '%s\n' "$candidate"
}

evidence_directory() {
 local relative=$1 candidate resolved
 case "$relative" in var/lib/dpkg|var/lib/dpkg/updates|var/lib/dpkg/info|var/log/journal) ;; *) return 1;; esac
 candidate="$evidence_root/$relative"
 resolved=$(timeout --kill-after=1s 10s realpath "$candidate") || return 1
 test "$resolved" = "$candidate" && test -d "$candidate" && test ! -L "$candidate" || return 1
 printf '%s\n' "$candidate"
}

evidence_admindir() {
 local directory updates entry
 directory=$(evidence_directory var/lib/dpkg) || return 1
 evidence_file var/lib/dpkg/status >/dev/null || return 1
 updates=$(evidence_directory var/lib/dpkg/updates) || return 1
 shopt -s nullglob
 for entry in "$updates"/*; do
  test -f "$entry" && test ! -L "$entry" || return 1
 done
 printf '%s\n' "$directory"
}

# Diagnostics are stderr-only; raw command bytes never become frame syntax.
rescue_check() {
 local stage=$1
 shift
 printf 'TASK11_RESCUE_CHECK stage=%s outcome=begin\n' "$stage" >&2
 if "$@"; then
  printf 'TASK11_RESCUE_CHECK stage=%s outcome=pass\n' "$stage" >&2
 else
  printf 'TASK11_RESCUE_CHECK stage=%s outcome=fail\n' "$stage" >&2
  return 1
 fi
}

root_device_value() {
 local stage=$1 mode=$2
 shift 2
 (
  set +e
  printf 'TASK11_RESCUE_CHECK stage=%s outcome=begin\n' "$stage" >&2
  spool=$(mktemp "${TMPDIR:-/tmp}/cloud8021x-task11-root.XXXXXX") || {
   printf 'TASK11_RESCUE_CHECK stage=%s outcome=fail reason=spool\n' "$stage" >&2
   exit 1
  }
  trap 'rm -f "$spool"' EXIT
  timeout --signal=TERM --kill-after=1s 10s "$@" > >(head -c 1025 > "$spool") 2>&1
  status=$?
  wait
  bytes=$(wc -c < "$spool")
  encoded=$(head -c 1024 "$spool" | base64 | tr -d '\r\n')
  outcome=fail
  if test "$status" = 0 && test "$bytes" -le 1024; then
   value=$(cat "$spool")
   case "$mode" in
    single) if test "$(wc -l < "$spool")" -eq 1 && [[ -n $value && $value != *$'\n'* && $value != *$'\r'* ]]; then outcome=pass; fi;;
    comparison) outcome=pass;;
   esac
  fi
  printf 'TASK11_RESCUE_CHECK stage=%s outcome=%s status=%d bytes=%d value_b64=%s\n' "$stage" "$outcome" "$status" "$bytes" "$encoded" >&2
  test "$outcome" = pass || exit 1
  printf '%s\n' "$value"
 )
}

check_root_device() {
 local root_line major source fs options extra vda_major root_uuid evidence_uuid
 root_line=$(root_device_value root-findmnt-read single findmnt -n -r -o MAJ:MIN,SOURCE,FSTYPE,OPTIONS /) || return 1
 read -r major source fs options extra <<< "$root_line"
 if [[ $major =~ ^[0-9]+:[0-9]+$ && $source = /dev/vda1 && $fs = ext4 && -z $extra ]]; then
  rescue_check root-fields true
 else rescue_check root-fields false; return 1; fi
 if [[ $options =~ ^[a-zA-Z0-9_.-]+(=[a-zA-Z0-9_.:-]+)?(,[a-zA-Z0-9_.-]+(=[a-zA-Z0-9_.:-]+)?)*$ ]]; then
  rescue_check root-options true
 else rescue_check root-options false; return 1; fi
 vda_major=$(root_device_value root-lsblk-read single lsblk -dnr -o MAJ:MIN /dev/vda1) || return 1
 rescue_check root-major-match test "$major" = "$vda_major" || return 1
 root_uuid=$(root_device_value root-partuuid-read single blkid -s PARTUUID -o value /dev/vda1) || return 1
 rescue_check root-partuuid-match test "$root_uuid" = d35a5af0-fb25-480f-ab0d-73615f73fc09 || return 1
 evidence_uuid=$(root_device_value evidence-partuuid-read single blkid -s PARTUUID -o value /dev/vdc1) || return 1
 rescue_check evidence-partuuid-match test "$evidence_uuid" = c2fb6dc1-ec0e-496c-9172-017c4cfd3483 || return 1
 printf 'TASK11_RESCUE_ROOT_DEVICE major_minor=%s source=%s fstype=%s options=%s root_partuuid=%s evidence_partuuid=%s\n' "$major" "$source" "$fs" "$options" "$root_uuid" "$evidence_uuid"
}

collector_main() {
 set -euo pipefail
 local prerequisite
 prerequisite=$(root_device_value uid-read comparison id -u)
 rescue_check uid-match test "$prerequisite" = 0
 prerequisite=$(root_device_value marker-read comparison cat /etc/cloud8021x-task11-rescue)
 rescue_check marker-match test "$prerequisite" = synthetic-readonly-v1
 prerequisite=$(root_device_value pid1-read comparison cat /proc/1/comm)
 rescue_check pid1-match test "$prerequisite" = systemd
 prerequisite=$(root_device_value net-read comparison ls /sys/class/net)
 rescue_check net-match test "$prerequisite" = lo
 prerequisite=$(root_device_value kernel-read comparison uname -r)
 case "$prerequisite" in *orbstack*) rescue_check kernel-not-orbstack false; return 1;; esac
 rescue_check kernel-not-orbstack true
 check_root_device
 test "$(timeout --kill-after=1s 10s blockdev --getro /dev/vdc)" = 1
 test "$(timeout --kill-after=1s 10s blockdev --getro /dev/vdc1)" = 1
 test "$(timeout --kill-after=1s 10s blockdev --getsize64 /dev/vdc)" = 8000000000
 test ! -e "$evidence_root"
 mkdir -m 0700 "$evidence_root"
 timeout --kill-after=1s 10s mount -t ext4 -o ro,noload,nodev,nosuid,noexec /dev/vdc1 "$evidence_root"
 trap 'timeout --kill-after=1s 10s umount "$evidence_root"' EXIT
 local mount_line
 mount_line=$(timeout --kill-after=1s 10s findmnt -n -r -o FSTYPE,OPTIONS,SOURCE,TARGET --mountpoint "$evidence_root")
 validate_evidence_mount "$mount_line"
 printf 'TASK11_RESCUE_READONLY_MOUNT %s\n' "$mount_line"
 bounded_probe boot cat /proc/sys/kernel/random/boot_id /proc/uptime /proc/1/comm
 bounded_probe filesystem df -B1 "$evidence_root"
 bounded_probe superblock dumpe2fs -h /dev/vdc1
 local path dir entry count=0
 if path=$(evidence_file var/log/dpkg.log); then
  bounded_probe dpkg-log-stat stat -c '%s %y %n' "$path"
  bounded_probe dpkg-log-tail tail -c 24576 "$path"
 else printf 'EVIDENCE_UNAVAILABLE dpkg-log\n'; fi
 if path=$(evidence_file var/lib/dpkg/status); then
  bounded_probe status-stat stat -c '%s %y %n' "$path"
  bounded_probe status-sha sha256sum "$path"
 else printf 'EVIDENCE_UNAVAILABLE status\n'; fi
 if dir=$(evidence_directory var/lib/dpkg/updates); then
  bounded_probe updates-inventory find "$dir" -mindepth 1 -maxdepth 1 -printf '%f %s\n'
  shopt -s nullglob
  for entry in "$dir"/[0-9][0-9][0-9][0-9]; do
   count=$((count+1)); test "$count" -le 64 || { printf 'EVIDENCE_LIMIT updates\n'; break; }
   if path=$(evidence_file "var/lib/dpkg/updates/${entry##*/}"); then
    bounded_probe update-sha sha256sum "$path"
   fi
  done
 fi
 if dir=$(evidence_admindir); then
  bounded_probe effective-packages dpkg-query --admindir="$dir" -W '-f=${Package}\t${Version}\t${Architecture}\t${Status}\t${Triggers-Pending}\t${Triggers-Awaited}\n'
 fi
 for entry in var/lib/dpkg/info/perl-modules-5.40.list var/lib/dpkg/info/perl-modules-5.40.list-new; do
  if path=$(evidence_file "$entry"); then
   bounded_probe perl-list-stat stat -c '%s %y %n' "$path"
   bounded_probe perl-list-lines wc -l "$path"
  else printf 'EVIDENCE_UNAVAILABLE %s\n' "$entry"; fi
 done
 if path=$(evidence_file etc/systemd/system/task11-nested-prep.service); then
  bounded_probe unit-sha sha256sum "$path"
  bounded_probe unit-bytes head -c 8192 "$path"
 fi
 if dir=$(evidence_directory var/log/journal); then
  bounded_probe journal-boots journalctl --directory="$dir" --list-boots --no-pager
  bounded_probe journal-units journalctl --directory="$dir" --no-pager -o short-monotonic -n 100 -u task11-nested-prep.service -u cloud-final.service -u serial-getty@hvc0.service
  bounded_probe journal-kernel journalctl --directory="$dir" --no-pager -o short-monotonic -k -n 50
 else printf 'EVIDENCE_UNAVAILABLE persistent-journal\n'; fi
 printf 'TASK11_RESCUE_COLLECTION_COMPLETE_NOT_INSTALL_ACCEPTANCE\n'
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
 if [[ ${1:-} == --collect ]]; then
  collector_main
 else
  # This is the sole external output path. The bound includes the final frame.
  exec > /dev/hvc0 2>&1
  set +e
  bounded_collection /bin/bash "$0" --collect
  result=$?
  timeout --kill-after=1s 10s systemctl --no-block poweroff >/dev/null 2>&1
  exit "$result"
 fi
fi
