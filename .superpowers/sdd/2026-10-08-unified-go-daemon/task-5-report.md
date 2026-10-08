# Task 5 implementation report

Status: implementation complete; controller review/push pending. Base `002b89d`,
branch `codex/unified-go-daemon`, draft PR 39. One implementer; no subagents,
production/vendor/Fleet/cloud requests, deployment, push, merge, or release.

## Delivered scope

- Read-only UniFi and Meraki HTTPS adapters normalize configured sites, APs,
  supported switch ports, VLAN IDs/names, and hardware identifier mappings into
  shared domain types. Stable authenticator IDs contain provider/site/device;
  every lookup key also includes provider and site. NYC display name remains
  exactly `32 Avenue of the Americas`; names are never used to identify trust.
- UniFi Cloud Connector uses the configured console ID, integration site IDs,
  offset/count/totalCount pagination, and adopted-device detail reads for ports.
  Duplicate IDs, inconsistent offsets/counts/totals, missing pages and bounds fail
  the affected scope. Source discovery independently reads paginated `/hosts`,
  selects exactly the pinned console, rejects missing/duplicate/blocked hosts,
  takes public IPv4 addresses from `ipAddress` and `reportedState.wans[].ipv4`,
  deduplicates/sorts /32s, and timestamps the successful authenticated fetch.
  Resource `updatedAt` is never freshness evidence.
- Meraki reads organization devices and wireless BSSID status with same-resource
  Link pagination; joins hardware MACs on both serial and network; reads each
  configured network, switch ports, and appliance VLANs or named VLAN profiles.
  Conflicting hardware identity joins and MAC ownership retain tombstones.
  MAC normalization accepts colon, dash, dotted and bare formats, including a
  Called-Station SSID suffix. Meraki does not guess BSSID offsets.
- The legacy UniFi base-MAC +1..7 last-byte heuristic is preserved only for AP
  details exposing `features.accessPoint`, as `Authenticator.InferredMACs`.
  It never wraps an octet, never claims to be advertised, loses to exact hardware
  or advertised aliases, and conflicting inferences resolve unavailable. This is
  display enrichment only; it cannot affect location/source/auth/VLAN authority.
- Transport forbids redirects, origin changes, URL credentials and hostile or
  ambiguous pagination links. Requests have bounded timeouts, responses are
  bounded, pagination has page/record limits, Meraki aggregate JSON is bounded,
  and 429 retries are at most three with cancelable capped waits. Errors omit
  credentials, URLs and controller bodies. All fixture keys/IDs are synthetic.
- Atomic local metadata indexes support concurrent readers without a full cache
  clone per request. Failed/unsupported scopes retain successful data and original
  timestamps. VLAN capability/freshness is independent of successful AP refresh;
  an unknown VLAN 403/404 is failed rather than fresh empty. Explicit non-network
  product types are unsupported; an empty supported inventory is available.
- Development disk caches are private, atomically written and bound to provider
  origin/configuration/credential digest/scope. Persisted metadata documents are
  similarly bound; configuration changes cannot reuse another controller's old
  metadata. No API request occurs in metadata lookup or VLAN encoding. A fake
  inventory-only registration has neither signaling nor discovery capabilities.
- Both built-in adapters expose the existing standards encoder; unchanged Wi-Fi
  numeric attributes are 13/6/decimal-string VLAN. Core policy and Sacramento
  opt-out were not changed. Meraki WAN discovery remains explicitly absent;
  static RADIUS clients remain usable.
- Real `sites sync` constructs providers from typed config and calls the shared
  sync service. Dry-run fetches and checks actual configured scopes without cache
  or metadata writes. Successful scopes publish even when an optional home scope
  fails, while the caller receives a failure summary for the failed scope.

## Root source security and transaction

`Applier.Apply` validates all configured client ranges and exact candidate scope,
original timestamps, unique canonical public IPv4 /32s, and cross-client overlaps.
It independently invokes a root-side `Verifier` for fresh authenticated evidence
from the pinned configured console and requires exact set equality. Repeating a
legitimate site ID in daemon JSON does not authenticate fabricated addresses.
Wrong scope, fabricated set, stale/failed evidence, /0, private/multicast/loopback,
broad prefixes and cross-client overlap reject before mutation. Configured static
CIDRs remain separately trusted and do not inherit discovered TTL.

The root entrypoint requires effective root and `/etc/cloud-8021x/config.yaml`,
reopens that fixed configuration through root-owned unwritable directory
components, ignores caller configuration objects/overrides for actual operations,
and reads only the configured candidate from a pinned private producer directory.
Descriptor-relative no-follow opens, owner/mode/regular-file/single-link checks,
byte limits, atomic rename and directory fsync protect inputs and publications.
No caller-selected executable, URL, root destination or command proxy exists.

`--candidate-sha256` accepts only a 64-lowercase-hex SHA-256 of the canonical
`json.Marshal([]domain.SourceCandidate)` document. Scheduled callers must pass
this exact persisted-claim digest. Replacement candidates reject before privileged
verification/mutation. Direct administrative root application may omit it.

The narrow typed transaction snapshots actual files and the fixed firewall,
installs rendered clients, validates FreeRADIUS, activates it, checks health,
converges the exact firewall ranges/disabled state, checks service health again,
rechecks original candidate age, and only then commits public applied state.
A failed step restores old clients, validates/reactivates them, converges the old
firewall, and restores old state. Cleanup has an independent bounded context.
Incomplete rollback reports reconciliation required; no new freshness is granted.
Dry-run performs authenticated verification and actual read-only snapshots, prints
non-secret client/range/node effects, and writes/restarts/patches nothing.

The firewall interface permits only `SourceRanges` and `Disabled` patches. Reads
must match the configured `allow-radius-{primary,secondary}-discovered` resource,
network, INGRESS direction, exact node target tag and UDP 1812/1813; extra source
or target principals, denied rules, broadened/invalid source ranges, or changed
identity fail. Disabled empty plans use only the legacy documentation /32
sentinel. Polling is bounded. No GCP credentials or actual GCP adapter were added.

Public state contains only a configuration SHA-256 and source candidates, never
resolved secrets or secret file references. Its configuration identity includes
provider origin, pinned console, configured client/location/medium/profile,
static ranges, secret references and max age. Changed protected configuration
invalidates old dynamic trust while static fallback continues.

## Durable ownership and reconciliation

Controller approved a narrow Task 3 storage extension because generic `Claim`
can claim another pending ID while a previous source revision is uncertain.
`postgres.Store.ClaimSource(ctx,node,owner,lease)` uses a per-fixed-node advisory
transaction lock; blocks active leased/started and unresolved quarantine across
all candidate revisions; moves expired started work to retained quarantine; and
fences expired generations. Primary and secondary are independent resources.
Generic `Claim` explicitly refuses `sources:` kinds. No schema change.

`jobs/network.ApplyJob` reserves the full candidate under `sources:<node>`, claims
using `SourceCoordinator`, decodes the exact persisted claimed payload, commits
`StartAttempt` before the typed callback, and records success or conservative
uncertainty afterward. A new caller's candidate cannot replace the claimed bytes.
Unknown starts perform no external I/O. Errors after start retain uncertainty and
block later revisions; the implementation does not assume errors prove no mutation.

`Applier.ReconcileApplied` is read-only: fresh root controller proof must still
match the attempted addresses, and `FileOperations.VerifyApplied` requires exact
rendered client bytes, exact original public state/config hash, fixed firewall
identity/ranges/disabled state and actual service health. Evidence contains hashes,
fixed node/network identity and controller observation times, with the same
canonical candidate digest as the scheduled guard. It never freshens expired
state or repeats an external operation. Task 9 persists this authenticated evidence
against the exact work ID/generation through `postgres.ReconcileSuccess`.
If current controller evidence differs or actual state cannot be proven, work
stays blocked for explicit reconciliation; there is no blind resend path.

## Exact downstream APIs and installation contracts

Task 6:

- `app.SourceConfig(config.Config) (sources.Config,error)` derives all binding
  trust from immutable RadiusClient/location/provider config.
- `sources.ReadState() (State,error)` authenticates root ownership and unwritable
  ancestry of the fixed published state; load this outside the auth hot path.
- `sources.Allowed(cfg,state,configuredClientID,actualSource,now)` and
  `sources.AuthenticatedClient(...)` preserve original TTL/static fallback and
  derive neutral context solely from the already-authenticated configured client.
  Task 6 must integrate this with the current concrete static `policy.TrustMap`;
  merely installing discovered FreeRADIUS clients does not extend that map.
- `network.Store.Resolve(provider,site,calledStation,vlan,now,maxAge)` and `Ports`
  are local display-only reads. `Replace` atomically publishes the full configured
  document; `Publish` supports scoped successful updates.

Task 8:

- Populate `RuntimeServices.SourceDependencies`, a function returning the typed
  root `sources.Verifier` and `sources.Operations` from re-read protected config.
  `app.RootVerifier` plus uncached `SourceDiscoveryFromConfig` supplies actual
  HTTPS pinned-console reads; installation controls protected credentials.
- `sources.NewFileOperations(radius,firewall,target,secrets)` fixes destinations.
  Implement `Radius.Validate`, `Activate`, `Healthy`; `Firewall.Read`, `Patch`;
  and `SecretReader.ReadSecret` with protected resources only. `FirewallTarget`
  is the configured project/node/network. No shell text is accepted by these APIs.
- `/etc/cloud-8021x/sources/`: root 0700; `clients.conf` and `apply.lock`: root 0600.
  The include contains RADIUS secrets. **Activate requires a root-started restart,
  not a freerad-UID reload**; actual native process behavior is Task 6/8 proof.
  The daemon must not join the freerad group or gain access to this include.
- `/var/lib/cloud-8021x-source-state/`: root-owned unwritable ancestry, normally
  0755; `state.json`: atomically replaced root 0644, intentionally daemon-readable
  and non-secret. Candidate/cache/metadata private directories: their producer
  0700 with protected ancestry; files 0600. Never install candidate paths beneath
  daemon-replaceable ancestor directories. Root config also has protected ancestry.
- Actual installed UID/sudo rules, fixed service commands, GCP authenticated
  adapter/operation observation and target identity checks remain Task 8.
  Without installed dependencies, `sources apply` returns a real error.

Task 9:

- `app.NetworkServiceFromConfig(cfg,store,dry,hc)` / `Service.Sync(ctx,dry)` is
  shared by command and schedule; `app.NetworkRegistryFromConfig` supplies
  inventory and optional signaling/discovery separately.
- `app.SourceDiscoveryFromConfig(cfg,hc)` returns uncached pinned `Discovery`
  entries. `jobs/network.Discover(ctx,entries,path,dry)` collects/writes candidate
  data only; it never invokes privilege. Root revalidation remains mandatory.
- `ApplyJob{Coordinator,Owner,Node,Apply}.Run(ctx,candidateBytes)` requires the
  source-specific coordinator and passes claimed candidate JSON to the callback.
  The installed callback must stage the bytes in the configured private path and
  invoke only the fixed helper with `--candidate-sha256` of those canonical bytes.
- Source application uses a protected local root flock and a two-minute operation
  context. Durable source leases are three minutes and finalization is bounded.
  Use authenticated `ReconcileApplied` evidence for uncertain work, never generic
  Claim or a new revision as an uncertainty bypass.
- Before `Radius.Activate`, Task 8/9 must implement the separate shared backend
  maintenance gate and actual peer-readiness check so independent per-node source
  jobs cannot restart both HA backends simultaneously. No such gate is fabricated
  in Task 5. Full schedules, daemon lifecycle, native state loading and HA are 9.

Task 8/10 configuration/example migration:

```yaml
network:
  providers:
    - id: nyc-unifi
      kind: unifi
      base_url: https://api.ui.com/v1
      console_id: <pinned-console-id>
      scopes: [<integration-site-id>]
      credential: {file: <single-unifi-key-file>}
    - id: sacramento-meraki
      kind: meraki
      base_url: https://api.meraki.com/api/v1
      organization_id: <pinned-organization-id>
      scopes: [<network-id>]
      credential: {file: <meraki-key-file>}
  discovery:
    enabled: true
    max_age: 15m
    candidate_file: <private-producer-directory>/candidate.json
    bindings:
      - {provider_id: nyc-unifi, client_id: <existing-radius-client-id>}
    firewall:
      project: <configured-project>
      node: radius-primary # radius-secondary on that node
      network: https://www.googleapis.com/compute/v1/projects/<project>/global/networks/<network>
```

Provider instances for multiple UniFi consoles share exactly one credential
reference; no fallback/multiple-key selection. Location site IDs belong to provider
scopes. Bindings name existing clients of that configured provider; console,
location, secret and medium are derived, never supplied by candidates. One console
cannot discover multiple clients/locations. Meraki discovery is unsupported;
optional home metadata can fail independently from office metadata and static
RADIUS. Existing metadata-free policy fixtures still validate without new pins;
real sites factory refuses missing console/organization pins. Task 10 must update
examples/Terraform/installation mappings rather than infer those IDs.

## Actual RED evidence

1. Initial `go test ./internal/network ./internal/adapters/unifi ./internal/privileged/sources`
   failed with undefined `Store`, `New`, `Binding`, `State`, `Plan`, `Config` and
   `Applier`, before implementation of the tested behavior.
2. `go test ./internal/network -run TestFailedVLANRefreshCannotEraseOrFreshenLabel`
   failed with missing VLAN capability/timestamp fields before separating VLAN
   freshness from AP refresh.
3. `go test ./internal/adapters/meraki -run TestAmbiguousHardwareJoinNeverLabelsEitherMAC`
   failed `ambiguous serial mapping attributed AABBCCDDEE01`. Conflicting hardware
   serial joins now tombstone the identity instead of labeling both MACs.
4. `go test ./internal/storage/postgres -run TestPostgresSource` failed with missing
   `ClaimSource` before the per-node transactional source guard was implemented.
5. `go test ./internal/privileged/sources -run TestFirewallRejectsBroadExistingSourceBeforeMutation`
   failed `unsafe existing firewall scope accepted`; /0 and invalid rollback
   snapshot ranges now reject before mutation.
6. `go test ./internal/network -run TestExactMACPrecedenceAndInferredAliasCollisionTombstones`
   failed with missing `InferredMACs` before implementing explicit lower-priority
   aliases and adjacent-AP collision/precedence behavior.

Development corrections: private filesystem fixtures were explicitly chmod 0700
(the Go test subdirectory was not private); a test initially compared the whole
metadata document even though failure status for an unsupported home may change,
then correctly checked retained successful timestamp/data. Final lint found five
style-only issues (HTTP constants, error capitalization, equivalent boolean form),
which were fixed. No diagnostic commands were delegated to the user.

## Actual GREEN evidence

- Focused provider/store/app/config/source suites passed throughout development.
  Fake TLS servers exercise exact routes, credentials, full pagination, repeated
  tokens/hostile links, offsets/counts/IDs, bounded 429, cancellation, redirects,
  site failures, AP hardware/BSSID joins, switch ports, VLAN profiles, empty versus
  unsupported versus malformed scopes, and no signaling vendor I/O.
- `C8021X_PG_FIXTURE_TASK=task5 scripts/test_postgres.sh -run TestPostgresSource`
  passed against actual PostgreSQL 16 with TLS, runtime role and race enabled:
  `TestPostgresSourceNodeSerializationAndUncertainty` and
  `TestPostgresSourceExpiredUnstartedGeneration`; `ok .../postgres 1.590s`.
  This proves two-worker same-node exclusion, cross-revision blocking, different
  node independence, expired-start quarantine, stale finish/start fencing,
  exact retained payloads and explicit reconciliation releasing the next revision.
- Source tests use actual temporary private files plus typed service/firewall
  operations. They prove rollback restores old client bytes/firewall/state,
  original timestamps survive, dry-run only snapshots, unsafe evidence does not
  reach operations, failed/never-converged firewall cannot commit freshness,
  final service health is checked, and read-only exact-state reconciliation does
  not write/patch/freshen. Config-origin changes invalidate dynamic trust while
  static ranges survive; public state contains no secret/reference strings.
- `go test -race ./...` passed all root packages. This ordinary root invocation
  skips environment-gated PostgreSQL integration; the actual PG evidence above
  is separate. After final lint-only fixes, affected package tests passed. The
  final malformed `productTypes` self-review guard additionally passed
  `go test -race ./internal/adapters/meraki`.
- `goimports` applied to every changed/new Go file. Final `golangci-lint run`:
  `0 issues.` `git diff --check`: clean.
- `GOOS=linux GOARCH=arm64 go build -o <unique temporary binary> ./cmd/cloud-8021x`
  passed; its EXIT trap removed the binary.
- The labeled `cloud8021x.test=task5` PostgreSQL fixture was removed by the runner;
  a final `docker ps -a --filter label=cloud8021x.test=task5` returned no entries.
  The reserved native FreeRADIUS fixture and all unrelated containers were left
  alone. No unchanged SCEP/Python suite or live controller test was run.

## Rulings, self-review and limits

Controller recorded the explicit console/organization mapping, fresh root
revalidation, source-specific PG claim, readable root state/config binding,
claimed digest guard, root-started restart/HA boundary and preserved inferred
UniFi aliases in the shared progress ledger. Costs: extra root controller reads;
explicit config/example migration; uncertain jobs can block a node pending real
reconciliation; inferred AP names remain weaker than advertised MAC mappings;
HA restart orchestration and installed permissions need downstream verification.

Self-review fixed ambiguous hardware joins, independent VLAN freshness, unsafe
existing firewall ranges, missing product-type capability shape, exact claimed
candidate fencing, public-state config binding, and explicit root-restart semantics.
No unresolved implementation blocker is known in Task 5. This is not a production
readiness claim: no real vendor scope coverage, GCP operation convergence, installed
root/freerad/daemon permission boundary, or native HA service restart has been tested.
Task 6/8/9/10 requirements above remain real work, not successful stub operations.

Primary route/shape references used (no real consoles): existing legacy refresher,
`vlan_names.py` and `radius_sources.py`; official UniFi adopted device details
https://developer.ui.com/network/v10.6.106/getadopteddevicedetails ; official Meraki
https://developer.cisco.com/meraki/api-v1/get-organization-wireless-ssids-statuses-by-device/
and https://developer.cisco.com/meraki/api-v1/get-network-vlan-profiles/ . No public
example tokens or tenant IDs from documentation were used in code or fixtures.
