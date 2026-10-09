# Datadog-only ownership handoff

This is a generated provider-only entrypoint for the **existing Datadog resource owner**. It contains the same JSON dashboards, monitors and pipelines as the authoritative root `datadog*.tf` sources. It is not a second owner and must not be applied while another state manages any of these remote IDs. The disabled native dashboard companion stays outside both active modules.

Generate or check it from the repository root without any cloud/state access:

```sh
(cd tools/dashboard && go run . observability --root ../.. --output ../../terraform/observability)
(cd tools/dashboard && go run . observability --root ../.. --output ../../terraform/observability --check)
terraform -chdir=terraform/observability init -backend=false
terraform -chdir=terraform/observability validate
terraform -chdir=terraform/observability test
```

The generator reads only the named monitoring source files, rejects unresolved/unsupported references, and emits `observability.tf`, `versions.tf` and the closed `ownership-handoff.json` inventory. Do not hand-edit those generated files. Inputs are reviewed nonsecret query/project/physical-host values. Supply Datadog credentials through the private operator environment (`DD_API_KEY`, `DD_APP_KEY`), never VM configuration or tfvars. The mock tests use neither credentials nor a remote backend.

## Separately approved ownership transfer

No transfer, import, backend access, remote plan or apply is authorized by these implementation fixtures. Before an approved transfer:

1. Freeze Terraform writes in the existing foundation owner and the new observability owner. Record the exact current source state lineage/serial and resource addresses. Retain encrypted, access-controlled offline backups of both state snapshots and backend configuration; work on separate copies, never the only backups.
2. Fill a **separate reviewed copy** of `ownership-handoff.json` with each existing remote dashboard/monitor/pipeline ID at the exact source/destination address. Keep absent, disabled optional resources null. Do not invent IDs or allow a new resource to replace an existing one. Record the exact source versions and destination backend prefix, distinct from blue foundation, green compute and private administration.
3. Under the separately approved transfer procedure, move only the populated Datadog addresses into that destination state, or detach them without destruction and import those exact IDs. Reconcile source and destination serials and verify exclusive ownership before releasing either lock. Remove their declarations from the original owner's deployed configuration or replace them with `removed { destroy = false }` blocks there. Do **not** apply this branch's retired root compute configuration to blue. No automatic import or state operation is performed by this generator.
4. Initialize the destination with the reviewed protected backend configuration. Use the reviewed inputs below and the matching saved remote plan. The destination must plan only no-op/update actions on the exact existing IDs. Run the mandatory offline guard on the JSON of that saved plan:

```sh
(cd tools/dashboard && go run . observability check-plan \
  --plan /private/review/observability-plan.json \
  --handoff /private/review/approved-ownership-handoff.json)
```

The guard rejects creation, import, deletion, replacement, changed IDs, omitted known owners, unknown addresses and all non-Datadog resources. An empty/unfilled handoff cannot pass. Review the exact saved plan and its host/query changes before a separately authorized apply. Keep both protected backups and the reverse ownership/address map for rollback; never apply both states as concurrent owners.

## Deliberate host admission

Copy green compute's nonsecret `observability_handoff.datadog_observability_hosts` exactly. The standalone entrypoint requires an explicit reviewed host set; it has no legacy fallback. For isolated green validation, use the two distinct green physical names. To deliberately show blue and green during staging, supply all four actual emitted names, including any historical blue suffix. The host selector and mandatory metric/log filter admit only that set even at `*`. At approved cutover, narrow it to the green pair; rollback restores the saved reviewed blue pair. Changing admission does not activate workers or move NAS/frontdoor traffic.

The root source retains null as its legacy two-host default for compatibility; that default is not available in this standalone owner. Never change green's physical hostname to impersonate blue. Live ingestion/rendering, no-data behavior and alert routing still require separately approved Datadog acceptance.

The existing HTTP/process service-check monitors preserve their IDs and group
results by physical `host`. Datadog service-check include tags use AND; listing
multiple host tags would match no hosts. Those monitors therefore discover all
hosts publishing the exact `service:smallstep-ca` and EC/RSA instance/process tags,
including staged/rollback servers. Retire those groups deliberately with the
observability owner. Dashboard service-check cards are individually scoped to
each admitted physical host; metric/log queries retain the explicit allowlist.
See [Datadog service-check scope semantics](https://docs.datadoghq.com/monitors/types/service_check/).
