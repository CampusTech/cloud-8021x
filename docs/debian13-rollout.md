# Debian 13 parallel rollout

The supported rollout creates two new Debian 13 instances through
`terraform/green`, with a separate application database provisioned through
`terraform/private-green` on the existing HA PostgreSQL service. Follow the
[ordered green deployment contract](deployment/parallel-green.md) and
[authenticated adoption workflow](parallel-adoption.md). Existing production
instances, disks, endpoints and accounting history remain available for rollback.
There is no in-place OS upgrade or legacy accounting-history import command.

Green must inherit the exact existing CA state: KMS signing identities, roots,
intermediates, SCEP decryption material, provisioners, CA databases and enrollment
frontdoors. It also preserves the authenticated policy and certificate observations
with their original timestamps, pending command ownership and Class/challenge/
broker identities. Missing or mismatched material blocks preparation; it never
authorizes initialization of replacement CA identities.

Stage and verify the complete architecture-specific release package closure,
application checksum, manifest/provenance pins, PostgreSQL CA and reviewed YAML.
Use a pinned Debian 13 image with the documented loader prerequisites. The source
capture binary runs on the existing hosts without installing the new packages.
Passive preparation validates installed configuration and material while the new
services remain stopped. It cannot establish running-service readiness or authorize
Fleet submissions, renewal, telemetry export or traffic switching.

Complete isolated activation and real packet, CA issuance/renewal, collector and
two-node failover checks before the separately reviewed cutover. Coordinate NAS
authentication and accounting destinations with the existing owner's EC, RSA and
broker backend groups. Keep the old instances and exact rollback configuration
until acceptance passes. Green starts a fresh accounting epoch; historical totals
are not continuous across the transition.

The retained root compute configuration is not the deployment entrypoint for this
rollout. Its existing-instance lifecycle protections still ignore only
`boot_disk[0].initialize_params[0].image` and prevent destruction. An image edit
does not upgrade an existing disk. Unrelated disk, network, machine and service
account changes remain visible, and replacement plans stay blocked. Do not remove
these protections to turn a fresh green deployment into replacement of blue.

`tests/test_terraform_lifecycle.py` verifies those protections with Google provider
5.45.2 and synthetic local state using `plan -refresh=false`. The fixture never
applies or reads production state. Local package and container tests do not prove
full systemd boot/reboot, actual cloud IAM/KMS, inherited production CA state or
physical-client acceptance. No production OS change, Terraform apply or instance
replacement is performed by these tests.
