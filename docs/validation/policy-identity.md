# Task 2 report: policy, identity and hardware VLAN encoding

Status: implemented and committed locally on `codex/unified-go-daemon` / PR #39.
Implementation commit: `1de3bc4317900f0ccf1a7260d4e4affcc3b8d220` (`feat: port verified certificate policy and local RADIUS authorization to Go`).
Starting implementation base: `b0cf38441541d6976f6fe866e03a9940a8ee372b`; parent documentation-only commit `252f283` arrived during implementation and was preserved.
The parent owns pushing. No production/cloud operations, legacy retirement, provider API requests, or webhook-package modifications occurred.

## Delivered behavior

- Provider-neutral device/group/location IDs, inventory and optional certificate/source-discovery/signaling interfaces, scoped network types, typed decisions and network attributes.
- Legacy inventory v1/v2 JSON compatibility, including absent versus empty certificate collection, empty v2 certificate/hardware maps, original fractional observation timestamps, stable normalized UUID/Windows aliases, fingerprint normalization, and sticky `null` ambiguity entries. Malformed display metadata becomes unavailable without altering authorization. Duplicate JSON keys, malformed records, missing timestamps, partial refreshes, and invalid publication are rejected.
- Atomic immutable snapshot generations. Authorization uses a read-only `InventoryView` and copies only the selected records instead of cloning the full cache per request. Export/migration can still use `SnapshotStore.Load()` and `PublishSnapshotFile`.
- Current enrollment, identity ambiguity, inventory freshness, independent certificate observation freshness, explicit attested-hardware resolution, group conflict rejection, fallback VLAN, unknown-location rejection, site opt-out, and wired no-VLAN decisions. Group/location rules select policy before any hardware encoding.
- Explicit legacy-serial mode rechecks current inventory, including resumed-session policy inputs; fingerprint mode has no CN fallback. The neutral `cloud-8021x-inventory` subject cannot authorize in legacy mode. Sticky downgrade protection uses the existing `/var/lib/cloud-8021x/fingerprint-enforced` marker by default.
- Neutral certificate readiness separates trusted certificate coverage from usable per-location VLAN decisions. Device-provider eligibility/unsupported classifications remain adapter responsibilities; no Fleet/Jamf branches were added to domain policy.
- Validated standard numeric UniFi/Meraki encoders emit untagged Tunnel-Type 13, Tunnel-Medium-Type 6, decimal-string Tunnel-Private-Group-Id. A fake device provider, network provider and alternate vendor signaling capability prove neutral contracts. Profiles enforce selected VLAN, type/count/size bounds, allowed attributes and conservative rejection of protected Class/EAP/TLS/MPPE/control state. Missing/unsupported profiles fail closed. Encoding never requests controller inventory.
- Sealed `identity.VerifiedCertificate` fields: only successful consumption of a private one-use handoff constructs a usable input. No arbitrary fingerprint, Class, username or NAS input can construct one.
- Exact leaf DER SHA-256 handoff, legacy plain fingerprint and attested JSON payload compatibility, exclusive creation, app-owned 0700 directory/0600 file, no overwrite, `NOFOLLOW`, nonblocking exclusive `flock`, regular-file/nlink/owner/mode/inode checks, unlink before age/content validation, strict non-future age below configured maximum (at most 120 seconds), replay/symlink/hardlink/lock/oversize rejection. Root helper records the already-read and X.509-parsed PEM bytes without reopening the replaceable temporary leaf file.
- Pinned EC issuer signature/issuer/CA/validity, clientAuth/non-CA leaf, exactly one ASCII-alphanumeric CN, exact Smallstep ACME provisioner OID/type marker and exact sole permanentIdentifier checks. Invalid recognition falls back to exact fingerprint binding.
- Exact existing `c8021x.1.` Class byte format and shared key compatibility: big-endian timestamp/12-byte nonce/32-byte leaf hash/uint16 VLAN/UTF-8 device ID, unchanged HMAC domain separator/site-length/site/MAC context, canonical unpadded URL-safe base64, 253-octet Class maximum, hex decoding and all existing MAC forms. Zero remains a signed no-VLAN sentinel. Missing, duplicate, malformed, wrong-key/context, future or expired bindings return nil attribution, never an authentication credential. Verification receives the original trusted receipt timestamp rather than processing time.
- Local authenticated POST `/authorize`, loopback peer check, private nofollow 0600 bearer token file, constant-time token-hash comparison, strict bounded JSON, complete-value arrays, concurrency and hard deadline bounds. A cancellation-ignoring capability cannot make HTTP exceed its deadline or release a still-running worker's bounded slot. Unknown routes (including accounting) return 404; no final-auth/accounting callback was added. Error bodies are generic and do not disclose certificates, secrets or handoff tokens.
- Complete policy HTTP construction via `freeradius/policy.FromConfig`, real typed FreeRADIUS REST serialization, `Handler.Server`, and a refreshable local snapshot store for Task 9 orchestration.
- Real `radius verify-leaf` positional arguments and named `--certificate-file` / `--session-token` flags, meaningful parsed-certificate dry-run, concrete `RuntimeServices` dispatch and main wiring. Remaining operations explicitly retain `ErrUnsupported` until their implementation tasks.

## Security/integration contracts for Tasks 6, 8 and 9

1. `runtime_user` defaults to `cloud8021x`; this must be a dedicated unprivileged account separate from root and freerad. The daemon gets no DAC/CHOWN capability and no CA-private-key/service-management access.
2. Provision `/run/radius-verified-leaves` as the fixed freerad-owned 0700 public-leaf input directory (`backends.radius_verify_leaf_dir`), directly under root-owned, non-group/other-writable ancestry. FreeRADIUS writes completed TLS-verification leaves as freerad-owned 0600 single-link regular files. Do not inherit a writable `/run/freeradius` parent or use the app-only handoff directory as the FreeRADIUS PEM tempdir. See the review-fix compatibility preflight below.
3. Provision `/run/radius-certificate-bindings` as app-owned 0700. The narrow root hook exclusively writes and chowns each 0600 handoff to the app UID; the daemon consumes it under its own UID. Existing freerad-owned handoff directories need explicit fenced migration by privileged bootstrap, not widened permissions.
4. Install a narrowly scoped freerad sudo rule for the fixed binary/config/subcommand invocation, e.g. `/usr/local/bin/cloud-8021x --config /etc/cloud-8021x/config.yaml radius verify-leaf <leaf-file> <server-session-token>`. No generic root command proxy. Cobra checks the fixed protected configuration **before its initial config load**, and RuntimeServices independently checks the real root UID and reloads the fixed file through NOFOLLOW/root-owned/regular/nlink=1/non-writable descriptor checks before any hook-controlled path access. Root dry-run is also gated. Thus extra `--config` flags cannot select attacker-owned YAML or arbitrary root paths. The executable's default effective-UID lookup is `os.Geteuid`; tests inject the lookup at command construction only, while operational services always recheck the actual OS UID.
5. Root-managed YAML is `/etc/cloud-8021x/config.yaml`, root-owned and not group/other writable. Pin the attested EC issuer and exact provisioner in it. Root bootstrap should persist/check the downgrade guard before activation and retain the original marker during migration/rollback.
6. Local REST request shape is JSON `{ "server": { "client_id": "configured-authenticated-client", "source_ip": "actual-transport-source" }, "handoff_tokens": ["server-token"], "calling_stations": ["actual-station"] }`. Both server fields must come from authenticated FreeRADIUS client/source state, never NAS packet attributes. Preserve **all** occurrences in arrays; do not select the first duplicate. Legacy mode uses `certificate_common_names` with exactly one server TLS CN and no handoff token. It must receive the authenticated TLS/resumption state, not an outer User-Name.
7. HTTP accept returns typed `reply:` attribute objects with `op :=`; reject/overload/deadline/auth/malformed failure must prevent EAP success and MPPE. Disable exact-leaf-mode TLS resumption unless the same exact identity can be restored. Configure native REST without reachability/precache startup coupling; Task 6 owns actual packet/template proof.
8. `AttributionInput` retains `Classes`, `ClassCount`, `Stations`, `StationCount`, trusted `LocationID`, and original `Receipt`. Native scalar+count intake must reject attribution when counts differ from one, even if storage retained only the first scalar. Never use Class as an auth credential or recompute a signed original VLAN from later membership.
9. `FromConfig(cfg, registry)` reads only local cache/key/token files and returns `(LocalService, Handler, error)`. `LocalService.Snapshots()` supplies the atomic store for Task 4 refresh jobs. Use `Handler.Server(cfg.Listeners.Policy.Address)` in Task 9 listener orchestration. No live Fleet/UniFi/Meraki/CA/Datadog construction is required on this path.
10. FreeRADIUS serialization currently supports the shipped standard numeric tunnel profile. Unknown/vendor dictionary mappings fail closed. A future vendor's validated typed signaling is supported by the neutral core; its FreeRADIUS dictionary mapping must be explicitly registered with that backend rather than accepting arbitrary attribute-name JSON/fragments.

## Contracts downstream can consume

- `domain.DeviceInventoryProvider.Fetch(ctx, InventoryScope) (DeviceSnapshot, error)`; `Complete` means the entire requested scope succeeded. `ManagedCertificateProvider` and `SourceDiscoveryProvider` are separate optional capabilities. Provider pagination/provenance/eligibility and Fleet normalization belong to Task 4/5.
- `domain.Device`, `DeviceRecord`, `DeviceMetadata`, `CertificateObservation`, `DeviceSnapshot`, `Snapshot`, `SnapshotStore`, `InventoryView`, `NetworkSnapshot`, `NetworkScopeResult`, `SourceCandidate`, typed `NetworkAttribute` / `NetworkReply` / `VLANAssignment` / `TrustedNetworkContext` / `Decision`.
- `domain.BuildSnapshot`, `DecodeSnapshot`, `PublishSnapshotFile`, `SnapshotStore.Publish` / validated `Set` / generation-preserving `View` / export `Load`, `Fresh`, `NormalizeIdentity`, `NormalizeFingerprint`.
- `policy.New(Config)`, `Engine.Authorize`, explicit `AuthorizeLegacy`, `ResolveCertificate`, `Config`, `CertificateReadiness`; `NewTrustMap` and `AuthenticatedClient(clientID, actualSourceIP)`.
- `identity.Handoff.Record` / `RecordPEM` / `Consume`, `VerifiedCertificate` read-only getters, `Attestation`, `RecognizeAttested`, `CheckDowngradeGuard`.
- `domain.VLANSignaler` is the neutral interface; `signaling.NewRegistry`, `Registration`, `Profile`, `AttributeRule`, `ValidateReply`, `StandardNumeric`, `NumericProfile`, `Builtins` implement/validate capabilities.
- `binding.ReadKey`, `Issue`, deterministic-test `IssueWithRandom`, `Verify`, `Attribution`, `MaxAge`, `Enrich`; invalid verification returns nil.
- `freeradius/policy.NewLocalService`, `FromConfig`, `NewHandler`, `HTTPOptions`, `Request`, `ServerContext`, `Result`, `RESTReply`, `Serialize`, `VerifyAttribution`, `AttributionInput`.
- `app.NewRuntimeServices`, `RunOptions.ConfigFile`, `RunOptions.VerifiedLeaf`, `VerifiedLeafOptions`; main now injects concrete runtime dispatch.

## Test-first evidence and verification

RED checkpoints (before corresponding implementation):

- Initial neutral domain/policy/binding/signaling tests failed on absent packages/types/functions; identity tests likewise failed on absent handoff/attestation/guard behavior.
- Local HTTP, CLI options/dispatch and ownership config tests failed on absent implementations/fields.
- `TestDeadlineReturnsEvenIfCapabilityIgnoresCancellationAndKeepsSlotBounded` failed with `handler exceeded deadline` (0.30 seconds for a 50 ms deadline); corrected by bounded worker ownership and timeout select.
- `TestBindingKeyWhitespaceCompatibility` failed with `legacy key newline invalid accounting binding key`; restored the existing stripped-key behavior for 4096-byte key plus newline.
- `TestPolicyFromConfigUsesOnlyLocalSnapshotsAndProtectedTokens` failed with `public bearer token file accepted`; private-file construction now rejects it.
- Required-timestamp, validated publication, immutable generation view and exact-read-PEM contracts were established before their respective implementation/refactor.
- Actual Cobra root-hook load-order test was added before command-level gating; the old path could load attacker-selected configuration before the runtime check. It now returns the fixed-protected-config error before generic config loading or dispatch.

GREEN final checks:

- `go test ./...`: passed (root and all original webhook packages).
- `go test -race ./...`: passed across all root packages, including relocated webhook behavior.
- After exact-read-PEM/root-dry-run hardening: `go test -race ./internal/identity ./internal/app ./internal/policy ./internal/adapters/freeradius/policy`: passed.
- After final Cobra load-order gate: `go test -race ./internal/app ./internal/adapters/freeradius/policy`: passed.
- `golangci-lint run`: final **0 issues**. Earlier findings (capitalized error/static conversion/unchecked new Set result) were corrected.
- `goimports -w` applied to changed Go packages; `git diff --check`: passed.
- `GOOS=linux GOARCH=amd64 go build ./...`: passed.
- `python3 -m unittest discover -s tests -p 'test_*.py'`: **293 tests passed**, 8.381 seconds. Existing HTTPError fixture ResourceWarnings were emitted; no failures.
- Legacy Class fixture independently generated with `scripts/radius_identity.py` using fixed nonce/time/key was matched byte-for-byte by Go. Snapshot and certificate tests preserve the security/freshness/ambiguity contracts of the retained Python helpers.

## Limits and remaining integration tasks

- Actual FreeRADIUS EAP-TLS/rlm_rest final packet, startup outage and MPPE ordering proof is Task 6; no templates/backend runtime were switched here.
- Positive root-to-different-UID ownership and installed protected configuration/sudo/systemd integration require Task 8's disposable Linux fixture. Tests here exercise private ownership/modes, adversarial configuration and local handoff behavior under the current non-root macOS test process. `TestRootDryRunDoesNotBypassFixedConfiguration` is deliberately skipped on non-root hosts; the actual Cobra root branch is separately exercised with the injected UID lookup and runtime mutating paths independently check real UID.
- Full serve lifecycle, shared database import of existing state/guard/key, schedules, event workers and all remaining command dispatch belong to Task 9. Accounting counter processing belongs to Task 3.
- Runtime Fleet host mapping/managed-certificate command provenance and full provider implementations belong to Tasks 4/5; the legacy provider-specific Python helpers remain intact until Task 10.
- `.gitignore` was corrected from broad `freeradius/` to root-only `/freeradius/` so tested source under `internal/adapters/freeradius/` is committed. The 23 relocated webhook source files were not modified.


## Review fix round 1: descriptor-confined privileged public-leaf input

Base: `c43c50ff0602473833e61faf08ed7f926272829a`. Scope is the Important Task 2 security finding only; snapshot metadata sanitization remains deferred to Task 4. No production operations, pushes, subagents, legacy changes, or unchanged Python/SCEP suite reruns occurred.

The root helper previously checked the input's lexical dirname and opened its full filename with `O_NOFOLLOW`, which did not reject ancestor symlinks. The new `identity.OpenLeafDirectory` walks from `/` using descriptor-relative `openat` with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` for every component. Root requires every ancestor to be root-owned and not group/other writable. The final directory must be owned by the fixed `freerad` account and exactly 0700. Directories must be linked; legitimate single-link overlay filesystem directories are allowed. A mutex pins the directory descriptor through reads and close. Renaming/replacing its pathname after opening cannot redirect the reader.

`LeafDirectory.Read` opens one basename relative to that descriptor using `O_NOFOLLOW|O_NONBLOCK`, checks producer UID, exact 0600 permissions, regular-file type and `nlink == 1` **before reading any bytes**, and retains the existing bounded PEM parser. The actual root RuntimeServices path selects the system `freerad` UID independently of caller flags/YAML. The parsed byte slice still goes directly to `RecordPEM`; no source pathname is reopened. Non-root dry-run permits private user ancestry and root-owned sticky temporary directories without granting root reads. Root never accepts sticky writable ancestry. Existing fixed-config gates still precede leaf access.

### Test-first evidence

- RED: `go test ./internal/app -run 'TestVerifyLeafRejects(ReplacedDirectoryComponentBeforeRead|HardlinkedInputBeforeRead)' -count=1` exited 1 before the confinement change. Both final-directory and ancestor replacements failed with `helper followed replaced directory component and accepted outside certificate`; hardlinked input failed with `helper accepted hardlinked public leaf outside the approved directory`. These fixtures contain a valid public X.509 leaf outside the approved directory, so failure is attributable to confinement rather than certificate parsing.
- RED: new identity directory tests initially failed to compile with `undefined: OpenLeafDirectory`, before implementation.
- RED: `go test ./internal/identity -run TestPrivilegedLeafAncestryRequiresRootAndNoWritableParent -count=1` exited 1 with `rejected protected root-owned single-link directory`. Directory checks were corrected to reject zero links rather than valid one-link overlay directories; leaf input checks retain exactly one link.
- Additional regressions prove pinned original bytes after pathname replacement; reject all symlink components, wrong directory ownership, public directories/files, replaceable writable ancestry, hardlinked/symlinked leaves and nested/absolute filename escapes. Root ancestor policy specifically rejects non-root ownership and writable sticky directories.

### Final verification

- Initial expanded focused race checkpoint: identity/app/config/local REST passed, but policy `TestCertificateFreshnessAmbiguityEnrollmentAndGroupConflicts` failed with `invalid, expired or consumed certificate handoff`. Its fixture sampled time before file creation and consumed at that timestamp plus only one millisecond, which can precede the completed write. The fixture now samples receipt time after `Record` completes; production future-time rejection is unchanged.
- `go test -race ./internal/policy -run TestCertificateFreshnessAmbiguityEnrollmentAndGroupConflicts -count=50`: passed (`ok .../internal/policy 1.217s`).
- `go test -race ./internal/identity ./internal/app ./internal/config ./internal/policy ./internal/adapters/freeradius/policy -count=1`: passed (identity 1.245s, app 1.171s, config 1.104s, policy 1.099s, local REST 1.247s).
- `goimports -w` applied to every changed Go file.
- `golangci-lint run`: exited 0, `0 issues.`
- `GOOS=linux GOARCH=amd64 go build ./internal/identity ./internal/app`: exited 0.
- `git diff --check`: exited 0.

### Task 6/8 contract amendment and compatibility preflight

Default/example input is now `/run/radius-verified-leaves`; handoffs remain `/run/radius-certificate-bindings`, app-owned 0700 with app-owned 0600 one-use entries. Task 8 must create the source directory freerad-owned 0700 under protected root ancestry and Task 6 must use that same directory for the completed TLS-verification hook's public PEM inputs, mode 0600. Every configured input-directory component must be a real directory, with protected root-owned ancestors and a freerad-owned final directory. The root helper rejects invalid configured paths before reading public leaf bytes, even if installation/preflight missed them.

An existing `/run/freeradius/verified-leaves` configuration is unsafe when `/run/freeradius` is freerad-writable; bootstrap must fail its compatibility preflight and move/configure the leaf source at the new protected path. Symlink aliases, hardlinks and permission widening are not migration mechanisms. Update the root-managed fixed configuration and TLS-hook leaf/temp directory together before activation. Keep the narrow fixed-config sudo contract and distinct daemon UID; no daemon root/freerad execution or DAC/CHOWN capability is added.

Positive installed root-to-freerad/application-UID ownership, protected `/run` ancestry and the full TLS-hook invocation remain assigned to Task 8's disposable Linux fixture, with native hook proof in Task 6. This fix's actual RuntimeServices regressions execute as the non-root macOS user, and separate root-policy checks cover ownership/writable-ancestor rules; Linux build passes. No positive root mutation claim is made here.


## Actual-root Linux confinement evidence

Controller-requested evidence follow-up on implementation `cb2003d697d99bf5f945bc7da0c049cbca1285de`; no source changes were needed. This supersedes the preceding limit for actual-root reader execution only. Installed cross-UID handoff ownership, narrow sudo invocation and native TLS integration still belong to Tasks 8/6.

Built the focused identity test binary for Linux arm64 and ran it as actual UID/GID 0 in a **new** disposable `debian:12-slim` container named `cloud8021x-task2-root-confinement-cb2003d`. The image was already cached (`--pull never`); the container had no network, all capabilities dropped, no-new-privileges, and only a read-only mount of the temporary test binary. Root tests create their private fixtures under `/run`, exercising the operational root-owned ancestor policy rather than the non-root temporary-directory exception.

Exact command (shell variables retain the unique artifact path):

```sh
set -e
leaf_test_artifact=$(mktemp /private/tmp/cloud8021x-task2-root-leaf.XXXXXX)
trap 'rm -f "$leaf_test_artifact"' EXIT
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o "$leaf_test_artifact" ./internal/identity
chmod 0555 "$leaf_test_artifact"
docker run --rm --pull never --name cloud8021x-task2-root-confinement-cb2003d --label cloud8021x.task=task2-root-confinement --network none --user 0:0 --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=$leaf_test_artifact,target=/identity-root.test,readonly" debian:12-slim /bin/sh -c 'id; exec /identity-root.test -test.v -test.run "^(TestLeafDirectory.*|TestPrivilegedLeafAncestryRequiresRootAndNoWritableParent)$" -test.count=1'
docker ps -a --filter name=cloud8021x-task2-root-confinement-cb2003d --format '{{.Names}}'
docker ps -a --filter name=cloud8021x-daemon-fr-c7d492 --format '{{.Names}} {{.Status}}'
```

Exit status **0**. Output:

```text
uid=0(root) gid=0(root) groups=0(root)
=== RUN   TestLeafDirectoryRejectsEverySymlinkComponent
--- PASS: TestLeafDirectoryRejectsEverySymlinkComponent (0.00s)
=== RUN   TestLeafDirectoryDescriptorRemainsPinnedAfterPathReplacement
--- PASS: TestLeafDirectoryDescriptorRemainsPinnedAfterPathReplacement (0.00s)
=== RUN   TestLeafDirectoryValidatesPrivateOwnershipAndUnwritableAncestry
--- PASS: TestLeafDirectoryValidatesPrivateOwnershipAndUnwritableAncestry (0.00s)
=== RUN   TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes
=== RUN   TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes/hardlink
=== RUN   TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes/symlink
=== RUN   TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes/public
=== RUN   TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes/escape
=== RUN   TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes/absolute
--- PASS: TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes (0.00s)
    --- PASS: TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes/hardlink (0.00s)
    --- PASS: TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes/symlink (0.00s)
    --- PASS: TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes/public (0.00s)
    --- PASS: TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes/escape (0.00s)
    --- PASS: TestLeafDirectoryRejectsHardlinkedSymlinkedOrPublicLeavesAndEscapes/absolute (0.00s)
=== RUN   TestPrivilegedLeafAncestryRequiresRootAndNoWritableParent
--- PASS: TestPrivilegedLeafAncestryRequiresRootAndNoWritableParent (0.00s)
PASS
cloud8021x-daemon-fr-c7d492 Up 52 minutes
```

The disposable container query returned no entries after `--rm`; the shell EXIT trap removed only its unique temporary binary. The pre-existing `cloud8021x-daemon-fr-c7d492` container was not mutated or removed. No production, network credentials, image pulls or unrelated suites were used. `git diff --check` passed for this report-only follow-up.
