# Accepted private NAS stdin contract (source decoder implemented; actual transport pending)

The controller owns actual namespace/cgroup/helper admission and independently verifies immutable plan and stage pins before supplying private stdin. The NAS helper has no path, owner, argv, endpoint, authority-config or generic-command override. This source checkpoint implements strict decoding/admission and prior-RSA key/chain validation; actual NAS client orchestration and protected runtime transport remain unfinished.

One strict object, schema1, maximum256KiB encoded bytes:

* `schema`: integer1.
* `request_bytes`: opaque base64 exact protected Request file bytes, decoded maximum64KiB, including leading/trailing whitespace/newline. They are decoded/validated only by the sole `acceptance/scenariocontract.DecodeRequest`; no copied Request schema, embedded-object canonicalization or fallback.
* `request_sha256`: actual independently pinned protected stage request digest, verified by controller before handoff and compared against exact decoded request_bytes. No re-marshalling to verify the pin.
* `plan_bytes`: opaque base64 exact immutable private NAS-plan bytes, decoded maximum64KiB.
* `plan_sha256`: independently pinned exact plan bytes, matching Request.PlanSHA256; never hash-only self-approval.
* `prior`: omitted for EC and initial original RSA; required for adopted/passive RSA renewal under the root-owned sole shared selector extension. Contains only `selection_bytes` (opaque exact shared CASelection bytes, maximum2KiB) and `result_bytes` (opaque exact retired shared Result bytes, maximum32KiB).

Duplicate/unknown/trailing fields, oversized bodies, selectors irrelevant to the action/authority, and any modified pin refuse. The root-owned sole shared Request now declares Authority and the phase-constrained prior-RSA selector. No second outer field/parser is created here. Authority must be selected before send. The private source decoder uses this sole shared declaration; actual runtime transport is still pending.

Controller verifies prior selection/result against the original protected stored request/result before handoff. NAS independently checks current Request.SelectionSHA256 against exact selection bytes; selection.ResultSHA256 against exact prior result bytes; same attempt and earlier issuance sequence; retired original-phase RSA issuance; actual serial/public DER digest; immutable root/intermediate/decrypter identity; persistent pinned synthetic RSA client key and actual preserved-chain verification. A changed/unbound prior object refuses. No fallback initial PKCSReq, copied authority private key, fixed-material expansion, overwritten prior result or fabricated issuance is permitted.

Case plans are exclusive immutable raw files under fixed `/var/lib/cloud8021x-task11/control/scenarios/plans`, selected only through a closed reviewed case filename list. Each case has its own independent irreversible attempt. Actual execution still requires reviewed complete driver/client source, helper/application/material/plan hashes, installed auxiliary descriptors and explicit root execution grant. Nothing in this contract proves actual retirement, product activation, passive denial, database continuity or traffic delivery.
