# Debian 13 rollout prerequisite

New RADIUS VMs use Debian 13. Existing VMs retain their current boot disks and OS:
Terraform ignores **only** `boot_disk[0].initialize_params[0].image` and refuses
instance destruction. Changing the configured image does not upgrade an existing
node. Disk size, network, machine, service account and all other changes remain
visible; replacement plans are intentionally blocked.

The real Google provider 5.45.2, using synthetic local state and
`plan -refresh=false`, replaces both existing auto-delete boot disks when only
the image changes without this protection. `tests/test_terraform_lifecycle.py`
checks that image changes no longer replace either node and unrelated boot disk
changes remain visible and blocked. The fixture never applies, reads production
state, discovers credentials or refreshes cloud resources.

Existing Debian 12 deployments need a separately approved, staged **in-place**
Debian 12 to 13 upgrade preserving the original disk, node identity and protected
transition evidence. This is an operator maintenance prerequisite, not an action
of the loader, daemon bootstrap or Terraform image setting:

1. Inventory both nodes, their actual OS/package versions, free disk space,
   static endpoints, CA state, SQL state, native detail/spool data, configuration,
   protected credentials and transition markers. Retain a restorable disk backup
   and tested console/disk recovery access before any OS change. Never delete the
   old MariaDB data or CA key material as cleanup.
2. Stage authenticated incoming and exact prior package archives. Retain the
   previous binary, configuration, package manifest and full cold rollback state.
   Complete the [protected two-node preparation](bootstrap/README.md) and
   [state capture/import](daemon-operations.md) prerequisites. Fence-only incoming
   preparation remains usable before the OS upgrade; it does not activate the
   new package set. A missing file/socket on a changed OS never proves fresh
   installation or permits skipping legacy SQL capture.
3. Obtain the separately approved single-node failover/quiescence window. Prove
   the other node's required readiness and preserve its authentication service.
   Capture the original legacy SQL state while its database remains available
   and after its original native/application writers are proven stopped. Keep
   the same static endpoint allocation; do not route clients to an unready node.
4. Perform the distribution's supported in-place upgrade on that node under the
   approved OS procedure. Reboot and verify Debian 13, mounted filesystems,
   identity, backups, exact state/credential ownership, connectivity and original
   transition evidence. Bootstrap refuses new package installation on any other
   OS; it does not upgrade the OS or relabel old native artifacts as compatible.
5. Run the protected bootstrap/import/activation and actual packet, policy,
   certificate, accounting, durable queue and readiness acceptance on that node
   before considering the peer's OS maintenance. Unknown peer state or an
   unresolved protected operation blocks progress. Repeat the approved process
   for the peer only after the first node can carry the required service.

Application package rollback is not an OS downgrade. A Debian 13 failure may
require the separately retained disk/OS recovery procedure in addition to exact
application/native archives and ledger sidecar reconciliation. Neither automated
replacement nor unattended zero-impact migration is promised.

Replacing an instance is a separate reviewed restore/rejoin lifecycle. Do not
remove `prevent_destroy`, use a fresh-state assertion, or treat a replacement
image as permission to discard existing node state. CA databases, signing keys,
static endpoint/failover boundaries and cold rollback records remain protected.
No production OS change, Terraform apply or instance replacement was performed
by the implementation or its synthetic tests.
