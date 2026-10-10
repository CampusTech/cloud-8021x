# Preparing the parallel green pair

Use [parallel adoption](parallel-adoption.md) as the operator workflow for source
key enrollment, signed source capture, passive preparation, activation and reverse
handoff. Use the reviewed infrastructure-rendered pair of strict YAML files and
verified artifacts in `/var/cache/cloud-8021x/artifacts`. Both green configurations
must share the immutable pair manifest, explicit `state_transition`, collection
epoch and original Class identity. Physical source/destination identities and all
four distinct public receipt-key pins must match the reviewed configuration.

## Source capture

On each original host, `bootstrap capture --incoming` persistently fences only
the known scheduler/helper writers and records their original process/flock/file
proofs. It captures signed policy/certificate state and pending Fleet command
provenance with original observation times. Original native RADIUS and both CA
services continue. Accounting, SQL/checkpoint and outbox history are excluded.
Transfer each root-only signed receipt to its corresponding green role through
authenticated transport, preserving ownership and mode 0600.

## Passive green preparation

On each green host, `bootstrap prepare --incoming` validates its physical identity,
source signatures, private application database/CA pin, existing CA ACLs, KMS
public keys and inherited CA/server/enrollment material. Missing, partial, disabled
or unreadable CA material fails closed; preparation never initializes or renews
it to make adoption succeed. Preserve the original Class identity and trust.

Persistent activation barriers precede package changes. Native RADIUS, CAs, Go
workers, renewal, source mutation and monitoring exporters stay stopped through
preparation and reboot. Preparation establishes an immutable empty accounting
epoch in the separate green application database and retains original pending
certificate-command guards. Uncertain submission and missing/404 responses remain
quarantined. Authorization comes from the signed source receipts.

## Interrupted preparation and activation

Retain the original incoming files, configuration, release, source receipts and
reported maintenance attempt. Recover preparation with the exact
`bootstrap prepare --incoming --resume-attempt N` procedure in parallel adoption.
It requires original helper PID/start death, stopped services and matching
shared/local installation evidence. A completed installation is acknowledged;
a partial installation restores saved state while retaining passive barriers.
After that rollback, run ordinary preparation again. Expiry alone never proves
process exit, and deleting receipts cannot establish a safe retry.

Refresh both source captures immediately before activation, transfer them, and
re-run ordinary preparation on both completed passive nodes to publish the final
receipts. Source fence proofs expire after ten minutes; transfer never refreshes
certificate observations. Follow the primary/secondary/primary activation sequence
and exact activation recovery in parallel adoption. Shared worker authority
requires both publications and authenticated peer readiness.

The owned fixtures exercise separate file/process, PostgreSQL, packet and CA
contracts. They do not establish production cloud adoption, a real systemd reboot,
both-node traffic cutover or physical client renewal acceptance. Those remain
staging and separately reviewed deployment gates.
