#!/bin/bash
# Runs only in the zero-NIC development VM. Never a product provisioning script.
# Service stdout/stderr stay on the bounded guest journal. Serial is optional.
canary_phase_begin() {
 if [[ -n ${canary_phase:-} ]]; then
  printf 'TASK11_NESTED_PHASE phase=%s event=end status=0\n' "$canary_phase"
 fi
 canary_phase=$1
 printf 'TASK11_NESTED_PHASE phase=%s event=begin\n' "$canary_phase"
}

canary_export_journal() {
 local console=$1
 (
  set +e
  spool=$(mktemp "${TMPDIR:-/run}/task11-journal.XXXXXX") || exit 1
  trap 'rm -f "$spool"' EXIT
  # Join both capture processes inside one deadline; process substitution plus
  # bare wait can leave the spool reader running after the query returns.
  pipeline_status=$(timeout --signal=TERM --kill-after=1s 10s /bin/bash -c '
   journalctl -b -u task11-nested-prep.service --no-pager -o short-monotonic 2>&1 | head -c 262001 > "$1"
   printf "%s %s" "${PIPESTATUS[0]}" "${PIPESTATUS[1]}"
  ' bash "$spool")
  capture_status=$?
  query_status=unavailable; collector_status=unavailable
  status_pattern='^([0-9]{1,3}) ([0-9]{1,3})$'
  if [[ "$pipeline_status" =~ $status_pattern ]]; then
   query_status=${BASH_REMATCH[1]}; collector_status=${BASH_REMATCH[2]}
  fi
  bytes=$(wc -c < "$spool")
  truncated=0; test "$bytes" -le 262000 || truncated=1
  printf 'TASK11_JOURNAL_QUERY_EXIT=%s truncated=%s collector_status=%s capture_status=%s\n' "$query_status" "$truncated" "$collector_status" "$capture_status" >&2
  # A failed console open/write is confined to this child, never the EXIT handler.
  timeout --signal=TERM --kill-after=1s 10s /bin/bash -c '
   exec > "$4" || exit "$?"
   head -c 262000 "$1" || exit "$?"
   printf "\nTASK11_JOURNAL_EXPORT query_status=%s truncated=%s collector_status=%s capture_status=%s\n" "$2" "$3" "$5" "$6"
  ' bash "$spool" "$query_status" "$truncated" "$console" "$collector_status" "$capture_status"
  write_status=$?
  test "$write_status" = 0 || exit "$write_status"
  test "$capture_status" = 0 && test "$query_status" = 0 && test "$collector_status" = 0 && test "$truncated" = 0
 )
}

# Failure observations only: never restart, repair, or weaken the reboot guard.
canary_reboot_diagnostics() {
 timeout --signal=TERM --kill-after=1s 10s /bin/bash -c '
  export LC_ALL=C
  printf "TASK11_REBOOT_TERMINAL reboot_exit=%s leader_exit=%s boot_read_exit=%s polls=%s\n" "$1" "$2" "$3" "$4"
  public_value() {
   printf "TASK11_REBOOT_VALUE %s_bytes=%s %s=%q\n" "$1" "${#2}" "$1" "${2:0:1024}"
  }
  public_value before "$5"; public_value after "$6"; public_value leader "$7"
  machinectl show task11-nested-canary --property=Leader,State,Service,Class --no-pager 2>&1 | head -c 4096
  statuses=("${PIPESTATUS[@]}")
  printf "\nTASK11_REBOOT_MACHINE_STATUS exit=%s collector=%s limit_bytes=4096\n" "${statuses[0]}" "${statuses[1]}"
  systemctl show task11-nested.service --property=ActiveState,SubState,Result,ExecMainStatus,MainPID --no-pager 2>&1 | head -c 4096
  statuses=("${PIPESTATUS[@]}")
  printf "\nTASK11_REBOOT_UNIT_STATUS exit=%s collector=%s limit_bytes=4096\n" "${statuses[0]}" "${statuses[1]}"
  journalctl -b -u task11-nested.service --no-pager -o short-monotonic -n 100 2>&1 | head -c 32768
  statuses=("${PIPESTATUS[@]}")
  printf "\nTASK11_REBOOT_JOURNAL_STATUS exit=%s collector=%s limit_bytes=32768 completeness=not_asserted\n" "${statuses[0]}" "${statuses[1]}"
 ' bash "${reboot_status:-not-attempted}" "${leader_status:-not-attempted}" "${boot_read_status:-not-attempted}" "${reboot_poll:-0}" "${before-}" "${after-}" "${leader-}"
}

canary_serial_status() {
 local console=$1 kind=$2 status=$3 status_pattern='^[0-9]{1,3}$'
 case "$kind" in EXPORT|SHUTDOWN) ;; *) return 2;; esac
 [[ "$status" =~ $status_pattern ]] && test "$status" -le 255 || return 2
 # Append only a closed-name numeric frame; open and write share one deadline.
 timeout --signal=TERM --kill-after=1s 2s /bin/bash -c '
  exec >> "$1" || exit "$?"
  printf "T11_%s=%s\n" "$2" "$3"
 ' bash "$console" "$kind" "$status"
}

canary_exit() {
 local result=$1 export_status shutdown_status
 trap - EXIT
 set +e
 printf 'TASK11_NESTED_STAGE_EXIT=%s phase=%s\n' "$result" "${canary_phase:-bootstrap}" >&2
 if [ "$result" != 0 ] && [ "${canary_phase:-}" = nested-reboot ]; then
  canary_reboot_diagnostics
  printf 'TASK11_REBOOT_DIAGNOSTICS_EXIT=%s\n' "$?" >&2
 fi
 timeout --signal=TERM --kill-after=1s 10s journalctl --sync
 canary_export_journal /dev/hvc0
 export_status=$?
 printf 'TASK11_NESTED_EXPORT_EXIT=%s\n' "$export_status" >&2
 canary_serial_status /dev/hvc0 EXPORT "$export_status"
 printf 'TASK11_STATUS_SERIAL_EXIT kind=EXPORT status=%s\n' "$?" >&2
 timeout --signal=TERM --kill-after=1s 10s systemctl --no-block poweroff
 shutdown_status=$?
 printf 'TASK11_NESTED_SHUTDOWN_EXIT=%s\n' "$shutdown_status" >&2
 canary_serial_status /dev/hvc0 SHUTDOWN "$shutdown_status"
 printf 'TASK11_STATUS_SERIAL_EXIT kind=SHUTDOWN status=%s\n' "$?" >&2
 exit "$result"
}

set -euo pipefail
trap 'canary_exit $?' EXIT
canary_phase_begin bootstrap
root=/var/lib/cloud8021x-task11
media=/run/task11-media
canary_phase_begin platform
test "$(cat /etc/cloud8021x-task11-fixture)" = synthetic-only-v1
test "$(cat /proc/1/comm)" = systemd
test "$(ls /sys/class/net)" = lo
case "$(uname -r)" in *orbstack*) exit 1;; esac
mkdir -p "$root" "$media"
mount -o ro /dev/vdb "$media"
cd "$media/archives"
canary_phase_begin archive-hashes
ls -la
sha256sum --check sha256sums
canary_phase_begin baseline-query
printf 'TASK11_LIVE_BASE_BEGIN\n'
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\t${Triggers-Pending}\t${Triggers-Awaited}\n' > "$root/current-dpkg.tsv"
cat "$root/current-dpkg.tsv"
# The read-only seed pins this helper's digest and carries the authenticated
# original dpkg status plus the exact approved development lock. Never infer
# installed state from a prior command's exit code or a marker file.
canary_phase_begin baseline-guard
cd "$media"
sha256sum --check fixture.sum
install -D -m 0755 "$media/fixture" /usr/local/libexec/task11-systemd-fixture
/usr/local/libexec/task11-systemd-fixture prerequisites
if [ ! -e "$root/live-base.tsv" ]; then
 dpkg-query -W -f='${Package}\t${Version}\n' | sort > "$root/live-base.tsv"
fi
printf 'TASK11_LIVE_BASE_MATCH\n'
canary_phase_begin service-start-policy
if [ -e /usr/sbin/policy-rc.d ]; then
 printf '#!/bin/sh\nexit 101\n' | cmp - /usr/sbin/policy-rc.d
else
 printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
 chmod 0755 /usr/sbin/policy-rc.d
fi
canary_phase_begin dpkg-install
dpkg --install "$media"/archives/*.deb
canary_phase_begin dpkg-audit
dpkg --audit > "$root/dpkg-audit"
canary_phase_begin audit-empty
test ! -s "$root/dpkg-audit"
canary_phase_begin final347
/usr/local/libexec/task11-systemd-fixture prerequisites --final
printf 'TASK11_OFFLINE26_INSTALLED\n'
canary_phase_begin private-network
# No background server or resolver is needed for the platform canary.
systemctl mask --now postgresql.service postgresql@.service ssh.service ssh.socket
sysctl -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1
# The outer has physically zero NICs. This bridge has no address or uplink.
ip link add c8021x11 type bridge
ip link set c8021x11 up
nft add table inet task11
nft 'add chain inet task11 input { type filter hook input priority 0; policy drop; }'
nft 'add chain inet task11 output { type filter hook output priority 0; policy drop; }'
nft 'add chain inet task11 forward { type filter hook forward priority 0; policy drop; }'
nft add rule inet task11 input iifname lo accept
nft add rule inet task11 output oifname lo accept
canary_phase_begin lower-copy
# All roots and device nodes below are owned by this true guest kernel; there
# are no Mac/Orb device, cgroup or filesystem binds.
test "$(df --output=avail -B1 / | tail -1)" -ge 3221225472
mkdir -p "$root/roots/lower" "$root/roots/upper" "$root/roots/work" "$root/roots/node"
copy_excludes=(dev proc sys run tmp media mnt var/lib/cloud8021x-task11 var/lib/cloud var/lib/postgresql var/log)
du_excludes=()
tar_excludes=()
for directory in "${copy_excludes[@]}"; do
 du_excludes+=("--exclude=/$directory")
 tar_excludes+=("--exclude=./$directory")
done
source_bytes=$(du -sx -B1 "${du_excludes[@]}" / | cut -f1)
test "$source_bytes" -le 1610612736
printf 'TASK11_COPY_SOURCE_BYTES=%s\n' "$source_bytes"
# Preserve holes, keep original exclusions, and bound archive payload before
# extraction. A truncated stream fails under pipefail; no success is inferred.
tar --sparse --one-file-system --numeric-owner -C / "${tar_excludes[@]}" -cf - . \
 | dd bs=1M count=1664 iflag=fullblock status=none \
 | tar --numeric-owner -C "$root/roots/lower" -xf -
lower_bytes=$(du -sx -B1 "$root/roots/lower" | cut -f1)
test "$lower_bytes" -le 1879048192
printf 'TASK11_LOWER_COPY_BYTES=%s\n' "$lower_bytes"
for directory in dev proc sys run tmp media mnt var/log var/lib/cloud; do mkdir -p "$root/roots/lower/$directory"; done
chmod 1777 "$root/roots/lower/tmp"
: > "$root/roots/lower/etc/machine-id"
printf '%s\n' task11-nested-canary > "$root/roots/lower/etc/hostname"
for unit in task11-nested-prep.service task11-canary.service cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service postgresql.service postgresql@.service ssh.service ssh.socket; do
 rm -f "$root/roots/lower/etc/systemd/system/$unit"
 ln -s /dev/null "$root/roots/lower/etc/systemd/system/$unit"
done
mount -t overlay overlay -o "lowerdir=$root/roots/lower,upperdir=$root/roots/upper,workdir=$root/roots/work" "$root/roots/node"
test "$(df --output=avail -B1 / | tail -1)" -ge 1073741824
# Pre-create only the owned VM's loop0 node. The child receives a private /dev;
# it creates its own control/device nodes with these same guest-kernel numbers.
if [ ! -e /dev/loop0 ]; then mknod /dev/loop0 b 7 0; fi
canary_phase_begin nested-start
systemd-run --unit=task11-nested --property=Delegate=yes --property=KillMode=mixed \
 --property=RestartForceExitStatus=133 --property=SuccessExitStatus=133 \
 --property=DevicePolicy=closed '--property=DeviceAllow=/dev/loop-control rw' \
 '--property=DeviceAllow=block-loop rwm' \
 /usr/bin/systemd-nspawn --boot --keep-unit --machine=task11-nested-canary \
 --directory="$root/roots/node" --network-bridge=c8021x11 --private-users=no --console=pipe
leader=''
for _ in $(seq 1 100); do
 leader=$(machinectl show task11-nested-canary --property=Leader --value 2>/dev/null || true)
 if [ -n "$leader" ]; then
  state=$(timeout 2s nsenter -t "$leader" -m -p -u -n -C -r -w /usr/bin/systemctl is-system-running 2>/dev/null || true)
  case "$state" in running|degraded) break;; esac
 fi
 sleep .2
done
test -n "$leader"
canary_phase_begin nested-proof
# Degraded may reflect intentionally masked services; required PID1/probe checks
# below must still pass. Record the genuine container state, not a success stub.
nsenter -t "$leader" -m -p -u -n -C -r -w /bin/sh -s <<'NODE'
set -eu
test "$(cat /proc/1/comm)" = systemd
hostname
cat /proc/sys/kernel/random/boot_id
stat -fc %T /sys/fs/cgroup
cat /proc/1/cgroup
ip link set host0 up
ip address add 10.203.11.21/24 dev host0
ip -4 route show table all
ip -6 route show table all
nft add table inet task11
nft 'add chain inet task11 input { type filter hook input priority 0; policy drop; }'
nft 'add chain inet task11 output { type filter hook output priority 0; policy drop; }'
nft add rule inet task11 input iifname lo accept
nft add rule inet task11 output oifname lo accept
mkdir -p /var/lib/cloud8021x-task11/node-loop
test -e /dev/loop-control || mknod /dev/loop-control c 10 237
test -e /dev/loop0 || mknod /dev/loop0 b 7 0
truncate -s 16M /var/lib/cloud8021x-task11/node-loop.ext4
mkfs.ext4 -q -F /var/lib/cloud8021x-task11/node-loop.ext4
mount -o loop,nodev,nosuid,noexec /var/lib/cloud8021x-task11/node-loop.ext4 /var/lib/cloud8021x-task11/node-loop
printf '%s\n' task11-nested-persistent > /var/lib/cloud8021x-task11/node-loop/persistent-proof
sync
findmnt /var/lib/cloud8021x-task11/node-loop
losetup -j /var/lib/cloud8021x-task11/node-loop.ext4
umount /var/lib/cloud8021x-task11/node-loop
NODE
before=$(nsenter -t "$leader" -m -p -r -w /bin/cat /proc/sys/kernel/random/boot_id)
for kind in pid mnt net uts cgroup; do
 outer=$(readlink "/proc/1/ns/$kind")
 inner=$(readlink "/proc/$leader/ns/$kind")
 printf 'TASK11_NAMESPACE %s outer=%s inner=%s\n' "$kind" "$outer" "$inner"
 test "$outer" != "$inner"
done
printf 'TASK11_NODE_BEFORE=%s\n' "$before"
canary_phase_begin nested-reboot
reboot_status=0; leader_status=not-attempted; boot_read_status=not-attempted; reboot_poll=0
machinectl reboot task11-nested-canary || { reboot_status=$?; exit "$reboot_status"; }
after=''
for _ in $(seq 1 150); do
 reboot_poll=$((reboot_poll + 1)); leader_status=0; boot_read_status=not-attempted
 leader=$(machinectl show task11-nested-canary --property=Leader --value 2>/dev/null) || leader_status=$?
 if [ -n "$leader" ]; then
  boot_read_status=0
  after=$(nsenter -t "$leader" -m -p -r -w /bin/cat /proc/sys/kernel/random/boot_id 2>/dev/null) || boot_read_status=$?
 fi
 if [ -n "$after" ] && [ "$after" != "$before" ]; then break; fi
 sleep .2
done
test -n "$after"
test "$before" != "$after"
printf 'TASK11_NODE_AFTER=%s\n' "$after"
nsenter -t "$leader" -m -p -u -n -C -r -w /bin/sh -s <<'NODE'
set -eu
test "$(cat /proc/1/comm)" = systemd
test -e /dev/loop-control || mknod /dev/loop-control c 10 237
test -e /dev/loop0 || mknod /dev/loop0 b 7 0
mount -o loop,nodev,nosuid,noexec /var/lib/cloud8021x-task11/node-loop.ext4 /var/lib/cloud8021x-task11/node-loop
test "$(cat /var/lib/cloud8021x-task11/node-loop/persistent-proof)" = task11-nested-persistent
findmnt /var/lib/cloud8021x-task11/node-loop
umount /var/lib/cloud8021x-task11/node-loop
NODE
canary_phase_begin nested-cleanup
systemctl show task11-nested.service --property=ControlGroup,ActiveState,MainPID,Delegate
systemctl stop task11-nested.service
umount "$root/roots/node"
df -B1 /
printf 'TASK11_NESTED_PID1_CGROUP_NETWORK_LOOP_REBOOT_PASS\n'
