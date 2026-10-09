# Portable scenario transport contract

This development-only package shares strict request/result types between the
acceptance controller and the separate NAS/client module. It is not linked into
the shipping daemon. It contains no process, network, SQL or service executor.
Actual controller handlers and the installed four-node scenarios are separate
integration work; passing these tests does not establish installed acceptance.

`DecodeRequest` accepts a closed action with independently pinned original plan,
platform inventory, current enrollment, shipping application and NAS helper.
Node, session and issued-certificate selectors are action-specific; even an
explicit empty irrelevant selector is refused. Names derive only from a validated
`task11-` attempt and sequence1..24. `DecodeStage` additionally requires the
independent request SHA; ordinary controller stages retain their exact one-field
request. Callers must use protected exclusive files and activate the existing
fixed controller service, never launch a replacement stage process directly.

`DecodeResult` binds that exact request and accepts exactly one measured body.
Retirement is an assertion the actual controller must establish from retained
process identities and its empty operation cgroup before publishing; the wire
validator cannot inspect the kernel. `ValidateHistory` requires every previous
protected request and retired result, with unchanged immutable pins and sequential
nonoverlapping operation times. Callers must also refuse retained uncertain
requests/failures rather than rerunning them.

Accounting observations use the production Event, State and Interval types.
Durable work, receipt and reconciliation bytes use base64 `[]byte`, preserving
whitespace, escapes and full unsigned64-bit values. The selected synthetic NAS,
sessions and row relationships are bounded. Native packet ACKs are observations;
they do not prove ledger processing or telemetry delivery.

CA observations require the actual public DER to match the selected decimal
serial and hash. RSA SCEP has an actual metadata row. Genuine renewal of the
trusted original EC leaf may retain the absence of metadata; absence is explicit
and cannot be replaced by invented provisioner bytes. Original signer/chain,
actual CA rows across adoption and passive signing denial still need genuine
client, read-only database and service/API evidence outside this package.

Request bytes are bounded at64KiB, complete result bytes at8MiB and opaque
accounting material at5MiB. Unknown fields, duplicate keys, trailing documents,
mismatched action bodies, substituted pins and unretired predecessors refuse.
All error text is static; raw private input, Class, tokens and keys are omitted.
